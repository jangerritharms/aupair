import random
import logging
import copy
from collections import Counter
from hashlib import sha256

from src.pyipv8.ipv8.attestation.trustchain.block import UNKNOWN_SEQ

import src.communication.messages_pb2 as msg

from src.agent.base import BaseAgent
from src.chain.block import Block
from src.public_key import PublicKey
from src.communication.messaging import MessageHandler, MessageHandlerType
from src.communication.messages import NewMessage
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


class ProtectSimpleAgent(BaseAgent):
    """The ProtectSimple agent only stores on the chain the hashes of the data that was exchanged
    instead of all blocks. This way an agent still cannot lie but the chains remain as small as
    possible. However that agent needs to keep track of which data was received with which block.
    This happens with the RequestStorage.
    """

    _type = "Honest agent"

    def __init__(self, *args, **kwargs):
        super(ProtectSimpleAgent, self).__init__(*args, **kwargs)
        self.ignore_list = []
        self.replace_rules = {}
        self.knows_about_double_spender = {}
        self.double_spends = []
        self.request_cache = RequestCache()
        self.exchange_storage = ExchangeStorage()

    def request_protect(self, partner=None):
        """Requests a new PROTECT interaction with a partner. If no partner is passed as argument
        a random partner will be chosen from the known agents. The initiator sends his complete
        chain to the partner. The partner receives a PROTECT_CHAIN message with that chain attached.
        If the random agent is the agent itself or an agent with an existing unfinished request the
        request is cancelled.

        Keyword Arguments:
            partner {AgentInfo} -- Info of partner to perform interaction with (default: {None})
        """

        while partner is None or partner == self.get_info():
            partner = random.choice(self.agents)

        if self.request_cache.get(partner.address) is not None:
            self.logger.warning('Request already open, ignoring request with %s', partner.address)
            return
        if partner.address in self.ignore_list:
            return

        chain = self.database.get_chain(self.public_key)

        db = msg.Database(info=self.get_info().as_message(),
                          blocks=[block.as_message() for block in chain])
        self.request_cache.new(partner.address, RequestState.PROTECT_INIT)
        self.request_cache.get(partner.address).chain_length_sent = len(chain)
        self.com.send(partner.address, NewMessage(msg.PROTECT_CHAIN, db))

        self.logger.info("Start interaction with %s", partner.address)

    def step(self):

        if random.choice(self.choices):
            self.request_protect()

    def verify_chain_no_missing_blocks(self, chain, expected_length):
        """Verifies that a chain of an expected length is complete, so no blocks are missing. This
        is done by checking the list of sequence numbers of the blocks in the chain.
        
        Arguments:
            chain {[Block]} -- Chain to be verified
            expectedlength {int} -- Expected length of the chain.
        
        Returns:
            bool -- True of the chain is complete, False otherwise
        """
        # check missing blocks
        seq = [block.sequence_number for block in chain]
        if not Counter(seq[:expected_length]) == Counter(range(1, expected_length+1)):
            self.logger.error("Chain %s does not have the correct sequence, expected 1 to %d",
                              seq, expected_length)
            return False

        return True

    def verify_chain_not_shorter_than_known(self, chain):
        """Checks that the chain received is not shorter than we already know. If an agent shares
        less blocks than we know the agent has, he is trying to double spend or manipulate.
        
        Arguments:
            chain {[Block]} -- Chain to be verified
        """

        max_seq = self.database.get_latest(chain[0].public_key)
        if max_seq and chain[-1].sequence_number < max_seq.sequence_number:
            self.logger.error("Agent shared less blocks than we already know %s",
                              PublicKey.from_bin(chain[0].public_key).as_readable())
            return False
        
        return True

    def verify_chain_tx_ex_pairs(self, chain):
        """Verifies that each transaction on the chain can be paired with a previous exchange. The
        current mechanism forces agents to have one exchange for each transaction. Not performing
        an exchange previous to a transaction is seens as a manipulation attempt.
        
        Arguments:
            chain {[Block]} -- Chain to be verified
        """
        # check for enough exchanges: with protect each transaction should have an exchange before
        transactions = [block for block in chain if block.is_transaction()]
        exchanges = [block for block in chain if block.is_exchange()]
        for tx in transactions:
            exchange = next((block for block in exchanges
                            if block.public_key == tx.public_key and
                            block.link_public_key == tx.link_public_key and
                            block.sequence_number < tx.sequence_number), None)

            if exchange is None:
                self.logger.error("Not enough exchange blocks found")
                self.logger.error("Tx block %s has no matching exchange", tx)
                self.logger.error("Chain [%s]", ",".join(("%s" % block for block in chain)))
                return False

            exchanges.remove(exchange)

        return True

    def verify_chain_for_double_spend(self, chain, expected_length):
        """Verifies whether we know of any block in the shared chain which is part of a double
        spend.
        
        Arguments:
            chain {[Block]} -- Chain to be verified
        """
        for block in chain:
            own_block = self.database.get(block.public_key, block.sequence_number)
            if own_block and own_block.hash != block.hash:
                self.found_double_spend(own_block, chain)
                return False
            
        return True

    def verify_blocks_for_double_spend(self, blocks):

        for block in blocks:
            own_block = self.database.get(block.public_key, block.sequence_number)
            if own_block and own_block.hash != block.hash:
                return own_block
        
        return False

    def verify_chain(self, chain, expected_length):
        """Verifies the correctness of a chain received by another agent. First check is only if the
        chain is complete. 

        Arguments:
            chain {[Block]} -- Agent's complete chain

        Returns:
            bool -- Outcome of the verification, True means correct, False means fraud
        """

        result = True

        result = result and self.verify_chain_for_double_spend(chain, expected_length)
        result = result and self.verify_chain_no_missing_blocks(chain, expected_length)
        result = result and self.verify_chain_not_shorter_than_known(chain)
        result = result and self.verify_chain_tx_ex_pairs(chain)

        return result

    def get_blocks_for_exchanges(self, exchange_summary_blocks, exchanges, partner_key):
        """For each exchange block, retrieves the list of blocks that were in the exchange.
        
        Arguments:
            exchange_summary_blocks {[Block]} -- List of exchange blocks
        """
        # get the blocks that make up the exchanges
        exchange_blocks = []
        for block in exchange_summary_blocks:
            ex = exchanges.exchanges.get(block.hash)
            if ex is not None:
                if len(ex) == 0:
                    exchange_blocks.append([])
                else:
                    blocks = self.database.index(ex)

                    if len(blocks) == 0:
                        self.logger.error('Blocks not found in database')

                    for block1, block2 in self.replace_rules.get(partner_key, []):
                        if block1 in blocks:
                            blocks = [b if b.hash != block1.hash else block2 for b in blocks]

                    exchange_blocks.append(blocks)
            else:
                self.logger.error('Block is not mentioned in exchanges.')
                return []

        return exchange_blocks

    def known_double_spend(self, transfer_hash, blocks, public_key):
        for block1, block2 in self.double_spends:
            if block1 in blocks:
                replaced_blocks = [b if b.hash != block1.hash else block2 for b in blocks]
                if transfer_hash == blocks_to_hash(replaced_blocks).encode('hex'):
                    self.replace_rules.setdefault(public_key, []).append((block1, block2))
                    
                    self.logger.info("Solved by known double spend")
                    self.logger.info("Added replacement rule for agent %s",public_key)
                    return True
            if block2 in blocks:
                self.knows_about_double_spend.append(public_key)
                return True

        return False

    def verify_exchange(self, chain, exchanges):
        """Verfies whether the exchanges that an agent sends are matching the exchange blocks on his
        chain.

        Arguments:
            chain {[Block]} -- [description]
            exchange {{hash: Index}} -- [description]
        """
        partner_key = PublicKey.from_bin(chain[0].public_key).as_readable()
        # get exchange blocks on the chain
        exchange_summary_blocks = [block for block in chain if block.is_exchange()]

        # check 1: exchange and exchange blocks have the same length
        if not len(exchange_summary_blocks) <= len(exchanges):
            self.logger.error("exchanges and exchange blocks are not the same length")
            return False

        # get the blocks that make up the exchanges
        exchange_blocks = self.get_blocks_for_exchanges(exchange_summary_blocks, exchanges, partner_key)

        if not len(exchange_blocks) <= len(exchanges):
            self.logger.error("Exchange blocks don't match exchanges")
            return False

        # compare hashes
        for block, blocks in zip(exchange_summary_blocks, exchange_blocks):
            transfer_hash = block.get_relevant_exchange()
            if transfer_hash != blocks_to_hash(blocks).encode('hex'):
                if self.known_double_spend(transfer_hash, blocks, partner_key):
                    self.logger.error("Known double spend")
                    continue
                else:
                    self.logger.error("Known double spends: %s", ",".join("(%s, %s)" % (b1, b2) for b1, b2 in self.double_spends))
                    self.logger.error("Exchange block does not match a hash")
                    self.logger.error("Block: %s", block)
                    self.logger.error("Exchange blocks: %s", ",".join(("%s" % b for b in blocks)))
                    return block.hash

        return True

    def get_own_block_index(self):
        """Returns block index of this agents database.
        """
        return BlockIndex.from_blocks(self.database.get_all_blocks())

    def get_index_from_exchanges_and_chain(self, exchanges, chain):
        """Calculates the block index from the chain and exchanges of another agent.
        """
        partner_index = BlockIndex()

        for block_hash, index in exchanges.exchanges.iteritems():
            self.exchange_storage.exchanges[block_hash] = index
            partner_index = partner_index + index
        partner_index += BlockIndex.from_blocks(chain)

        return partner_index

    def found_double_spend(self, own_version, blocks):
        block_match = [b for b in blocks if b.public_key == own_version.public_key and
                           b.sequence_number == own_version.sequence_number]
        self.double_spends.append((own_version, block_match[0]))
        partner = self.get_partner_by_public_key(PublicKey.from_bin(own_version.public_key))
        self.ignore_list.append(partner.address)
        self.logger.info("Will ignore %s because of double spend",
                            partner.public_key.as_readable())

    def configure_message_handlers(self):
        super(ProtectSimpleAgent, self).configure_message_handlers()
        configure_protect(self)


def configure_protect(agent):

    @agent.add_handler(msg.PROTECT_CHAIN)
    def protect_chain(self, sender, body):
        """Handles a received PROTECT request. The agents receives a partner's chain who is
        requesting an exchange of endorsements and following interaction. The agent checks the chain
        for consistency. The chain should be complete and if it includes interactions it should also
        include endorsements. If there already exists an open, unfinished request with that agent,
        the request is rejected and a msg.PROTECT_REJECT message is sent. If verification checks out
        the agents requests a database index from the other agent. If the verification fails, a
        msg.PROTECT_REJECT message is sent and the initiator is added to the ignore list.

        Arguments:
            sender {Address} -- Address string of the agent.
            body {msg.Database} -- Body of the incoming message.
        """

        if self.request_cache.get(sender) is not None:
            self.logger.warning('Request already open, ignoring request from %s', sender)
            self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))
            return

        if sender in self.ignore_list:
            self.logger.warning('Agent %s is in ignore list', sender)
            self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))
            return

        chain = [Block.from_message(block) for block in body.blocks]

        self.request_cache.new(sender, RequestState.PROTECT_INIT, chain)
        self.request_cache.get(sender).chain_length_received = len(chain)
        verification = self.verify_chain(chain, len(chain))

        if verification:
            self.com.send(sender, NewMessage(msg.PROTECT_INDEX_REQUEST, msg.Empty()))
        else:
            self.logger.warning("Chain verification failed for sender %s", sender)
            self.ignore_list.append(sender)
            self.request_cache.remove(sender)
            self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))

    @agent.add_handler(msg.PROTECT_INDEX_REQUEST)
    def protect_index_request(self, sender, body):
        """Handles a received PROTECT_INDEX_REQUEST. A PROTECT exchange was accepted by both sides.
        The agent is required to send exchanges that list the blocks received from other agents. The
        agent keeps track of these in the exchange storage. If a request is found which matches the
        sender the agent sends a msg.PROTECT_INDEX_REPLY message to the responder of the PROTECT
        exchange.

        Arguments:
            sender {Address} -- Address string of the agent
            body {msg.Empty} -- Body of the incoming message.
        """

        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return

        message = self.exchange_storage.as_message()
        self.request_cache.get(sender).update_state(RequestState.PROTECT_INDEX)
        self.com.send(sender, NewMessage(msg.PROTECT_INDEX_REPLY, message))

    @agent.add_handler(msg.PROTECT_INDEX_REPLY)
    def protect_index_reply(self, sender, body):
        """Handles a received PROTECT_INDEX_REPLY. A PROTECT exchange is ongoing, the exchanges were
        received which should add up to the hashes stored on the chain. If a request for the sender
        is found, the agent checks which blocks the initiator of the PROTECT exchange has that the
        checking agent is not aware of and requests those.

        Arguments:
            sender {Address} -- Address string of the agent
            body {msg.ExchangeIndex} -- Body of the incoming message.
        """

        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return

        exchanges = ExchangeStorage.from_message(body)

        self.exchange_storage.add_exchange_storage(exchanges)
        partner_index = self.get_index_from_exchanges_and_chain(exchanges,
                                                                self.request_cache.get(sender).chain)

        db = (partner_index - self.get_own_block_index())
        db.remove(self.get_info().public_key)

        self.com.send(sender, NewMessage(msg.PROTECT_BLOCKS_REQUEST, db.as_message()))

        self.request_cache.get(sender).index = partner_index
        self.request_cache.get(sender).exchanges = exchanges
        self.request_cache.get(sender).update_state(RequestState.PROTECT_INDEX)

    @agent.add_handler(msg.PROTECT_BLOCKS_REQUEST)
    def protect_blocks_request(self, sender, body):
        """Handles a received PROTECT_BLOCKS_REQUEST. A PROTECT exchange is ongoing, the initiator
        received a request for blocks that initiator has above the responder. The initiator selects
        those from the database and sends them to the responder in a msg.PROTECT_BLOCKS_REPLY
        message. The uploaded data is stored in the request cache as it's hash will be stored on the
        exchange block created for this request.

        Arguments:
            sender {Address} -- Address string of the agent.
            body {msg.BlockIndex} -- Body of the incoming message.
        """

        if self.request_cache.get(sender) is None:
            logging.error('No open reqest found for this agent')
            return

        index = BlockIndex.from_message(body)

        blocks = []
        if len(index) == 0:
            self.request_cache.get(sender).transfer_up = ''
            self.request_cache.get(sender).transfer_up_index = BlockIndex()
        else:
            blocks = self.database.index(index)
            self.request_cache.get(sender).transfer_up = blocks_to_hash(blocks)
            self.request_cache.get(sender).transfer_up_index = index

        db = msg.Database(info=self.get_info().as_message(),
                          blocks=[block.as_message() for block in blocks])
        self.com.send(sender, NewMessage(msg.PROTECT_BLOCKS_REPLY, db))
        self.request_cache.get(sender).update_state(RequestState.PROTECT_EXCHANGE)

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
        self.logger.error("Verification returned %s", verification)

        if verification is True:
            own_chain = self.database.get_chain(self.public_key)
            own_index = BlockIndex.from_blocks(self.database.get_all_blocks())
            partner_index = self.request_cache.get(sender).index
            index = (own_index - partner_index)
            index.remove(PublicKey.from_bin(self.request_cache.get(sender).chain[0].public_key))

            sub_database = []
            if len(index) == 0:
                self.request_cache.get(sender).transfer_down = ''
                self.request_cache.get(sender).transfer_down_index = BlockIndex()
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

        self.exchange_storage.add_exchange_storage(exchanges)

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

    @agent.add_handler(msg.PROTECT_BLOCK_PROPOSAL)
    def protect_block_proposal(self, sender, body):
        """Handles a received PROTECT_BLOCK_PROPOSAL message. A PROTECT exchange is ongoing, the
        responder received the block proposal from the initiator. This includes the two hashes of
        the block sets that were exchanged between the two agents. The agent checks both hashes and
        if they check out the agent creates the block agreement, signs and stores it and replies to
        the initiator with the msg.PROTECT_BLOCK_AGREEMENT message.

        Arguments:
            sender {Address} -- Address string of the agent.
            body {msg.Block} -- Body of the incoming message.
        """

        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return

        block = Block.from_message(body)
        error = self.database.add(block)

        if error:
            self.logger.warning("Detected double spend of agent %s", PublicKey.from_bin(error.public_key).as_readable())

        index = BlockIndex.from_blocks([block])
        payload = {'transfer_down': blocks_to_hash([block]).encode('hex')}
        exchange_block = self.block_factory.create_new(self.get_info().public_key, payload)
        self.exchange_storage.add_exchange(exchange_block, index)

        new_block = self.block_factory.create_linked(block)
        self.com.send(sender, NewMessage(msg.PROTECT_BLOCK_AGREEMENT, new_block.as_message()))
        self.exchange_storage.add_exchange(new_block,
                                           self.request_cache.get(sender).transfer_up_index)
        self.request_cache.get(sender).update_state(RequestState.PROTECT_DONE)

    @agent.add_handler(msg.PROTECT_BLOCK_AGREEMENT)
    def protect_block_agreement(self, sender, body):
        """Handles a received PROTECT_BLOCK_AGREEMENT message. A PROTECT exchange is ongoing, the
        initiator received the block agreement from the responder. The initiator checks whether the
        block proposal and block agreement blocks include the same data and stores them in the
        database. The request is then concluded and removed from the request cache. Now the actual
        interaction can take place which is handled by the BaseAgent super-class.

        Arguments:
            sender {Address} -- Address string of the agent.
            body {msg.Block} -- Body of the incoming message.
        """

        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return

        block = Block.from_message(body)
        error = self.database.add(block)

        if error:
            self.logger.warning("Detected double spend of agent %s", PublicKey.from_bin(error.public_key).as_readable())

        block = Block.from_message(body)
        index = BlockIndex.from_blocks([block])
        payload = {'transfer_down': blocks_to_hash([block]).encode('hex')}
        exchange_block = self.block_factory.create_new(self.get_info().public_key, payload)
        self.exchange_storage.add_exchange(exchange_block, index)

        partner = next((a for a in self.agents if a.address == sender), None)
        self.request_interaction(partner)
        self.request_cache.get(sender).update_state(RequestState.PROTECT_DONE)

    @agent.add_handler(msg.BLOCK_PROPOSAL)
    def block_proposal(self, sender, body):
        if self.request_cache.get(sender) is None or \
                not self.request_cache.get(sender).in_state(RequestState.PROTECT_DONE):
            self.logger.error('No open reqest found for this agent')
            return

        block = Block.from_message(body)
        index = BlockIndex.from_blocks([block])
        payload = {'transfer_down': blocks_to_hash([block]).encode('hex')}
        exchange_block = self.block_factory.create_new(self.get_info().public_key, payload)
        self.exchange_storage.add_exchange(exchange_block, index)

        error = self.database.add(block)

        if error:
            self.logger.warning("Detected double spend of agent %s", PublicKey.from_bin(error.public_key).as_readable())

        new_block = self.block_factory.create_linked(block)
        self.com.send(sender, NewMessage(msg.BLOCK_AGREEMENT, new_block.as_message()))

        self.request_cache.remove(sender)

    @agent.add_handler(msg.BLOCK_AGREEMENT)
    def block_confirm(self, sender, body):
        if self.request_cache.get(sender) is None or \
                not self.request_cache.get(sender).in_state(RequestState.PROTECT_DONE):
            self.logger.error('No open reqest found for this agent')
            return

        block = Block.from_message(body)
        index = BlockIndex.from_blocks([block])
        payload = {'transfer_down': blocks_to_hash([block]).encode('hex')}
        exchange_block = self.block_factory.create_new(self.get_info().public_key, payload)
        self.exchange_storage.add_exchange(exchange_block, index)

        error = self.database.add(block)

        if error:
            self.logger.warning("Detected double spend of agent %s", PublicKey.from_bin(error.public_key).as_readable())

        self.logger.info("Exchange and transaction with %s completed", sender)

        self.request_cache.remove(sender)

    @agent.add_handler(msg.PROTECT_EXCHANGE_REQUEST)
    def exchange_request(self, sender, body):
        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return

        ex_hash = body.exchange_hash
        exchange_index = self.exchange_storage.exchanges[ex_hash]
        blocks = self.database.index(exchange_index)

        self.com.send(sender, NewMessage(msg.PROTECT_EXCHANGE_REPLY,
                                         msg.Database(info=self.get_info().as_message(),
                                                      blocks=[block.as_message() for block in blocks])))

    @agent.add_handler(msg.PROTECT_EXCHANGE_REPLY)
    def exchange_reply(self, sender, body):
        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return

        self.logger.error("Trying to detect the actual double spend")
        blocks = [Block.from_message(block) for block in body.blocks]
        
        result = self.verify_blocks_for_double_spend(blocks)

        if not result:
            self.logger.error("No error found in the exchange blocks")
            self.logger.error("Blocks: %s", ",".join(("%s" % b for b in blocks)))
            # if we find no error that means the other agent should also have
            # detected the wrong exchange
            self.logger.warning("Verification of %s's exchanges failed", sender)
            self.request_cache.remove(sender)
            self.ignore_list.append(sender)
            self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))

        if result:
            self.found_double_spend(result, blocks)
            partner = self.get_partner_by_public_key(PublicKey.from_bin(result.public_key))
            
            if partner.address == sender:
                self.logger.warning("Verification of %s's exchanges failed", sender)
                self.request_cache.remove(sender)
                self.ignore_list.append(sender)
                self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))
            else:
                request = self.request_cache.get(sender)
                if request.state == RequestState.PROTECT_EXCHANGE_CLARIFICATION_RESPONDER:
                    verification = self.verify_exchange(request.chain,
                                                        request.exchanges)
                    self.logger.error("Verification returned %s", verification)

                    if verification is True:
                        own_chain = self.database.get_chain(self.public_key)
                        own_index = BlockIndex.from_blocks(self.database.get_all_blocks())
                        partner_index = request.index
                        index = (own_index - partner_index)
                        index.remove(PublicKey.from_bin(request.chain[0].public_key))

                        sub_database = []
                        if len(index) == 0:
                            request.transfer_down = ''
                            request.transfer_down_index = BlockIndex()
                        else:
                            sub_database = self.database.index(index)
                            request.transfer_down = blocks_to_hash(blocks)
                            request.transfer_down_index = index
                        request.chain_length_sent = len(own_chain)

                        db = msg.ChainAndBlocks(chain=[block.as_message() for block in own_chain],
                                                blocks=[block.as_message() for block in sub_database],
                                                exchange=self.exchange_storage.as_message())
                        self.com.send(sender, NewMessage(msg.PROTECT_CHAIN_BLOCKS, db))
                        request.update_state(RequestState.PROTECT_EXCHANGE)

                    elif verification is False:
                        self.logger.error("Verification of %s's exchanges failed", sender)
                        self.request_cache.remove(sender)
                        self.ignore_list.append(sender)
                        self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))
                elif request.state == RequestState.PROTECT_EXCHANGE_CLARIFICATION_INITIATOR:
                    verification = self.verify_chain(request.chain, len(request.chain)) and \
                        self.verify_exchange(request.chain, request.exchanges)
                    transfer_down = BlockIndex.from_blocks(request.blocks)

                    if verification is True:
                        partner = next((a for a in self.agents if a.address == sender), None)
                        payload = {'transfer_up': self.request_cache.get(sender).transfer_up.encode('hex'),
                                'transfer_down': blocks_to_hash(request.blocks).encode('hex'),
                                'chain_up': self.request_cache.get(sender).chain_length_sent,
                                'chain_down': self.request_cache.get(sender).chain_length_received}
                        new_block = self.block_factory.create_new(partner.public_key, payload=payload)
                        self.com.send(partner.address, NewMessage(msg.PROTECT_BLOCK_PROPOSAL,
                                                                new_block.as_message()))
                        self.exchange_storage.add_exchange(new_block, transfer_down)
                        self.request_cache.get(sender).update_state(RequestState.PROTECT_BLOCK)
                    elif verification is False:
                        self.logger.warning("Verification of %s's exchanges failed", sender)
                        self.request_cache.remove(sender)
                        self.ignore_list.append(sender)
                        self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))

    @agent.add_handler(msg.PROTECT_REJECT)
    def protect_reject(self, sender, body):
        """Handles a received PROTECT_REJECT message. This message is sent when the agent that
        receives a message does not agree with the conditions of the request. Multiple reasons lead
        to such an event. When received, an agent is supposed to remove the request from the request
        cache in order to allow for more requests with that agent in the future.

        Arguments:
            sender {Address} -- Address of the sender of the request.
            body {msg.Empty} -- Empty message body.
        """

        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return

        self.logger.debug("Interaction cancelled with %s", sender)
        self.request_cache.remove(sender)
