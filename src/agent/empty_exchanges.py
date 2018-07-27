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

class EmptyExchangeAgent(ProtectSimpleAgent):

    _type = "DFR - empty exchanges"

    def configure_message_handlers(self):
        super(EmptyExchangeAgent, self).configure_message_handlers()
        configure_self_request(self)

    def verify_internal_state_for_transaction(tx, ex, chain_partner):
        result = True

        result = result and verify_chain_no_missing_blocks


def configure_self_request(agent):

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

        db = BlockIndex()

        self.com.send(sender, NewMessage(msg.PROTECT_BLOCKS_REQUEST, db.as_message()))

        self.request_cache.get(sender).index = partner_index
        self.request_cache.get(sender).exchanges = exchanges
        self.request_cache.get(sender).update_state(RequestState.PROTECT_INDEX)

    
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
        blocks = []
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
                       'transfer_down': '',
                       'chain_up': self.request_cache.get(sender).chain_length_sent,
                       'chain_down': 0}
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