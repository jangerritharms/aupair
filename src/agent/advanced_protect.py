import random
import logging
from hashlib import sha256
from collections import Counter

import src.communication.messages_pb2 as msg

from src.public_key import PublicKey
from src.agent.simple_protect import ProtectSimpleAgent
from src.communication.messages import NewMessage
from src.agent.request_cache import RequestState
from src.chain.block import Block, UNKNOWN_SEQ
from src.chain.index import BlockIndex
from src.agent.exchange_storage import ExchangeStorage
from src.agent.request_cache import RequestCache, RequestState


def blocks_to_hash(blocks):
    """Takes a list of blocks and creates a hash that includes the hashes of all blocks contained.

    Arguments:
        blocks {[Block]} -- List of blocks.
    """

    list_of_hashes = sorted([block.hash for block in blocks])
    hash_string = ''.join(list_of_hashes)
    if hash_string == '':
        return ''
    return sha256(hash_string).digest()

def verify_chain_no_missing_blocks(chain, expected_length):
    """Verifies the correctness of a chain received by another agent. First check is only if the
    chain is complete. 

    Arguments:
        chain {[Block]} -- Agent's complete chain

    Returns:
        bool -- Outcome of the verification, True means correct, False means fraud
    """

    # check missing blocks
    seq = sorted(list(set([block.sequence_number for block in chain])))
    if not Counter(seq[:expected_length]) == Counter(range(1, expected_length+1)):
        logging.error("Chain does not have the correct sequence, expected 1 to %d", expected_length)
        logging.error("%s", seq)
        return False

    # # check for enough exchanges: with protect each transaction should have an exchange before
    # transactions = [block for block in chain if block.transaction.get('up') is not None]
    # exchanges = [block for block in chain if block.transaction.get('transfer_down')]
    # for tx in transactions:
    #     exchange = next((block for block in exchanges
    #                     if block.public_key == tx.public_key and
    #                     block.link_public_key == tx.link_public_key and
    #                     block.sequence_number < tx.sequence_number), None)

    #     if exchange is None:
    #         self.logger.error("Not enough exchange blocks found")
    #         self.logger.error("Chain [%s]", ",".join(("%s" % block for block in chain)))
    #         return False

    #     exchanges.remove(exchange)

    return True


class ProtectAdvancedAgent(ProtectSimpleAgent):

    _type = "Replay verifier"

    def configure_message_handlers(self):
        super(ProtectAdvancedAgent, self).configure_message_handlers()
        configure_advanced(self)

    def verify_internal_state_for_transaction(tx, ex, chain_partner):
        result = True

        result = result and verify_chain_no_missing_blocks

    def replay_verification(self, original_chain, exchanges):
        transactions = [block for block in original_chain if block.is_transaction()]
        partner = self.get_partner_by_public_key(PublicKey.from_bin(original_chain[0].public_key))

        last_index = 0
        database = []
        for tx in transactions:

            # find matching exchange block, each transaction can be matched with an exchange
            ex_tx = None
            for block in reversed(original_chain[:tx.sequence_number]):
                if block.is_exchange() and block.link_public_key == tx.link_public_key:
                    ex_tx = block

            for block in original_chain[last_index:tx.sequence_number]:
                if block.is_exchange():
                    ex = exchanges.exchanges.get(block.hash)
                    if ex:
                        exchange = self.database.index(ex)
                        database.extend(exchange)
                database.append(block)

            expected_chain_length = -1
            if ex_tx.link_sequence_number == UNKNOWN_SEQ:
                expected_chain_length = ex_tx.transaction['chain_down']
            else:
                expected_chain_length = ex_tx.transaction['chain_up']

            # get the chain of transaction party
            chain = sorted([block for block in database if block.public_key == tx.link_public_key], key=lambda x: x.sequence_number)
            
            if len(chain) == 0:
                return False
            verification = verify_chain_no_missing_blocks(chain, expected_chain_length)

            if not verification:
                self.logger.error("REPLAY VERIFICATION chain not compiled correctly for transaction %s and exchange %s", tx, ex_tx)
                self.logger.error("Chain: %s", ",".join(("%s" % block for block in original_chain)))
                self.logger.error("Exchanges: %s", exchanges)
                return False

            #############################
            # At this point the chain seems to be in a complete state
            #############################

            # get exchange blocks on the chain
            exchange_summary_blocks = [block for block in chain[:expected_chain_length]
                                       if block.transaction.get('transfer_down') is not None]
            
            # get the blocks that make up the exchanges
            exchange_blocks = []
            for block in exchange_summary_blocks:
                if block.hash in exchanges.exchanges:
                    if len(exchanges.exchanges[block.hash]) == 0:
                        exchange_blocks.append([])
                    else:
                        blocks = self.database.index(exchanges.exchanges[block.hash])

                        for block1, block2 in self.replace_rules.get(partner.public_key.as_readable(), []):
                            if block1 in blocks:
                                blocks = [b if b.hash != block1.hash else block2 for b in blocks]

                        if len(blocks) == 0:
                            self.logger.error('Blocks not found in database')

                        exchange_blocks.append(blocks)
                else:
                    self.logger.error('Block is not mentioned in exchanges.')
                    self.logger.error("Block %s", block)
                    self.logger.error("Exchanges %s", exchanges)
                    self.logger.error("Original chain: [%s]", ",".join(("%s" % block for block in original_chain)))
                    self.logger.error("chain: [%s]", ",".join(("%s" % block for block in chain)))
                    return False
            
            if not len(exchange_blocks) <= len(exchanges):
                self.logger.error("Exchange blocks don't match exchanges")
                return False

            # compare hashes
            for block, blocks in zip(exchange_summary_blocks, exchange_blocks):
                if block.link_sequence_number == UNKNOWN_SEQ:
                    if block.transaction['transfer_down'] != blocks_to_hash(blocks).encode('hex'):
                        self.logger.error("REPLAY VERIFICATION wrong exchange hash")
                else:
                    if block.transaction['transfer_up'] != blocks_to_hash(blocks).encode('hex'):
                        self.logger.error("REPLAY VERIFICATION wrong exchange hash")
        return True

def configure_advanced(agent):

    @agent.add_handler(msg.PROTECT_BLOCKS_REPLY)
    def protect_blocks_reply(self, sender, body):
        """Handles a received PROTECT_BLOCKS_REPLY. A PROTECT exchange is ongoing, the responder
        received the blocks the initiator had more than himself. Now the responder can check that
        the blocks add up to all information of the agent as proven by the hashes of the exchange
        blocks on the chain of the initiator. If the check succeeds, the agent shows his agreement
        by sending his own chain and blocks that he has above the initiator in a
        msg.PROTECT_CHAIN_BLOCKS message. If the check fails, the agent sends a msg.PROTECT_REJECT
        message and adds the initiator to the ignore list.

        Arguments:
            sender {Address} -- Address string of the agent.
            body {msg.Database} -- Body of the incoming message.
        """

        if self.request_cache.get(sender) is None:
            logging.error('No open reqest found for this agent')
            return

        blocks = [Block.from_message(block) for block in body.blocks]

        error_blocks = self.database.add_blocks(blocks)

        if error_blocks:
            self.database.add_blocks(blocks, False)
            self.logger.warning("Detected double spend of agent %s", PublicKey.from_bin(error_blocks.public_key).as_readable())
        
        self.request_cache.get(sender).transfer_up = blocks_to_hash(blocks)
        self.request_cache.get(sender).transfer_up_index = BlockIndex.from_blocks(blocks)

        verification = self.verify_exchange(self.request_cache.get(sender).chain,
                                            self.request_cache.get(sender).exchanges)

        if verification is True:
            verification = self.replay_verification(self.request_cache.get(sender).chain,
                                                self.request_cache.get(sender).exchanges)
            if verification:
                own_chain = self.database.get_chain(self.public_key)
                own_index = BlockIndex.from_blocks(self.database.get_all_blocks())
                partner_index = self.request_cache.get(sender).index
                index = (own_index - partner_index)
                index.remove(PublicKey.from_bin(self.request_cache.get(sender).chain[0].public_key))

                sub_database = []
                if len(index) == 0:
                    self.request_cache.get(sender).transfer_up = ''
                    self.request_cache.get(sender).transfer_up_index = BlockIndex()
                else:
                    sub_database = self.database.index(index)
                    self.request_cache.get(sender).transfer_down = blocks_to_hash(blocks)
                    self.request_cache.get(sender).transfer_down_index = index
                self.request_cache.get(sender).chain_length_sent = len(own_chain)

                db = msg.ChainAndBlocks(chain=[block.as_message() for block in own_chain],
                                        blocks=[block.as_message() for block in sub_database],
                                        exchange=self.exchange_storage.as_message())
                self.com.send(sender, NewMessage(msg.PROTECT_CHAIN_BLOCKS, db))
                self.request_cache.get(sender).update_state(RequestState.PROTECT_EXCHANGE)

            else:
                self.logger.error("Verification of %s's exchanges failed", sender)
                self.request_cache.remove(sender)
                self.ignore_list.append(sender)
                self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))
        elif verification is False:
            self.logger.error("Verification of %s's exchanges failed", sender)
            self.request_cache.remove(sender)
            self.ignore_list.append(sender)
            self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))
        elif type(verification) is str:
            block_hash = verification
            self.logger.warning("Verification of hash was not correct, finding double spend")
            self.request_cache.get(sender).update_state(
                RequestState.PROTECT_EXCHANGE_CLARIFICATION_RESPONDER)
            self.com.send(sender,
                          NewMessage(msg.PROTECT_EXCHANGE_REQUEST,
                                     msg.ExchangeRequest(exchange_hash=verification)))

    @agent.add_handler(msg.PROTECT_CHAIN_BLOCKS)
    def proect_chain_blocks(self, sender, body):
        """Handles a received PROTECT_CHAIN_BLOCKS message. A PROTECT exchange is ongoing, the
        initiator received chain, blocks and exchange data from the responder. The
        initiator should check whether the responder is completely trustworthy and shares all his
        data. The chain and exchange data is verified and only if the data checks out the next step
        is done. That is the block proposal, all data is exchanged and both agents trust each other,
        an exchange block can be created which includes the hashes of both sets of exchanged blocks.
        If the verification fails the responder is added to the ignore list and a msg.PROTECT_REJECT
        is sent.

        Arguments:
            sender {Address} -- Address string of the agent.
            body {msg.ChainAndBlocks} -- Body of the incoming message.
        """

        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return

        chain = [Block.from_message(block) for block in body.chain]
        blocks = [Block.from_message(block) for block in body.blocks]
        exchanges = ExchangeStorage.from_message(body.exchange)
        self.request_cache.get(sender).chain = chain
        self.request_cache.get(sender).blocks = blocks
        self.request_cache.get(sender).exchanges = exchanges

        for block_hash, index in exchanges.exchanges.iteritems():
            self.exchange_storage.exchanges[block_hash] = index

        error_chain = self.database.add_blocks(chain)
        error_blocks = self.database.add_blocks(blocks)

        if error_chain or error_blocks:
            self.database.add_blocks(chain, False)
            self.database.add_blocks(blocks, False)
            self.found_double_spend(error_chain, chain)
            self.logger.warning("Detected double spend of agent %s", PublicKey.from_bin(error_chain.public_key).as_readable())

        self.request_cache.get(sender).transfer_down = blocks_to_hash(blocks)
        self.request_cache.get(sender).chain_length_received = len(chain)

        verification = self.verify_chain(chain, len(chain)) and self.verify_exchange(chain, exchanges)
        transfer_down = BlockIndex.from_blocks(blocks)

        if verification is True:
            verification = self.replay_verification(chain,
                                                    exchanges)

            if verification:
                partner = next((a for a in self.agents if a.address == sender), None)
                payload = {'transfer_up': self.request_cache.get(sender).transfer_up.encode('hex'),
                        'transfer_down': blocks_to_hash(blocks).encode('hex'),
                        'chain_up': self.request_cache.get(sender).chain_length_sent,
                        'chain_down': self.request_cache.get(sender).chain_length_received}
                new_block = self.block_factory.create_new(partner.public_key, payload=payload)
                self.com.send(partner.address, NewMessage(msg.PROTECT_BLOCK_PROPOSAL,
                                                          new_block.as_message()))
                self.exchange_storage.add_exchange(new_block, transfer_down)
                self.request_cache.get(sender).update_state(RequestState.PROTECT_BLOCK)
            else:
                self.logger.warning("Verification of %s's exchanges failed", sender)
                self.request_cache.remove(sender)
                self.ignore_list.append(sender)
                self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))
        elif verification is False:
            self.logger.warning("Verification of %s's exchanges failed", sender)
            self.request_cache.remove(sender)
            self.ignore_list.append(sender)
            self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))
        elif type(verification) is str:
            self.logger.warning("Verification of hash was not correct, finding double spend")
            self.request_cache.get(sender).update_state(
                RequestState.PROTECT_EXCHANGE_CLARIFICATION_INITIATOR)
            self.com.send(sender,
                          NewMessage(msg.PROTECT_EXCHANGE_REQUEST,
                                     msg.ExchangeRequest(exchange_hash=verification)))