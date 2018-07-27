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

        subject = self.get_partner_by_public_key(PublicKey.from_bin(original_chain[0].public_key))
        replacements = self.replace_rules.get(subject.public_key.as_readable(), [])
        should_ignore = []
        current_chain = []
        partner_chains = {}
        for block in original_chain:
            current_chain.append(block)

            if block.is_double_exchange():
                partner = self.get_partner_by_public_key(PublicKey.from_bin(block.link_public_key))
                current_index = self.get_index_from_exchanges_and_chain(exchanges, current_chain)
                expected_length = block.get_relevant_chain_length()
                partner_seq = current_index.get(block.link_public_key)

                if not Counter(partner_seq[:expected_length]) == Counter(range(1, expected_length+1)):
                    self.logger.error("Exchange block: %s", block)
                    self.logger.error("Current chain: %s", ",".join(("%s" % b for b in current_chain)))
                    self.logger.error("Exchanges: %s", exchanges)
                    self.logger.error("Current index: %s", current_index)
                    self.logger.error("REPLAY VERIFICATION: Chain does not have right sequence")
                    return False
                
                partner_chain_index = BlockIndex([(partner.public_key.as_bin(),
                                                   range(1, expected_length+1))])
                partner_chain = self.database.index_with_replacements(partner_chain_index,
                                                                      replacements)
                partner_chains[partner.public_key.as_readable()] = partner_chain

            if block.is_transaction():
                partner = self.get_partner_by_public_key(PublicKey.from_bin(block.link_public_key))

                if partner.public_key.as_bin() in should_ignore:
                    self.logger.error("REPLAY VERIFICATION Subject %s should have ignored partner %s",
                                      subject.public_key.as_readable(),
                                      partner.public_key.as_readable())
                    return False

                partner_chain = partner_chains.get(partner.public_key.as_readable())

                if not partner_chain:
                    self.logger.error("REPLAY VERIFICATION seems like transaction had no previous exchange")

                for partner_block in partner_chain:

                    if partner_block.is_exchange():
                        exchange = exchanges.exchanges.get(partner_block.hash)
                        if exchange:
                            exchange_blocks = self.database.index_with_replacements(exchange, replacements)
                            transfer_hash = partner_block.get_relevant_exchange()

                            if not transfer_hash == blocks_to_hash(exchange_blocks).encode('hex'):
                                for block1, block2 in self.double_spends:
                                    if block1 in exchange_blocks or block2 in exchange_blocks:
                                        should_ignore.append(block1.public_key)

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
                    self.request_cache.get(sender).transfer_down = blocks_to_hash(sub_database).encode('hex')
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
            if error_chain:
                self.found_double_spend(error_chain, chain)
            elif error_blocks:
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