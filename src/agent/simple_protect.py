import random
import logging
from collections import Counter

import src.communication.messages_pb2 as msg

from src.agent.base import BaseAgent
from src.chain.block import Block
from src.communication.messaging import MessageHandler
from src.communication.messages import NewMessage
from src.chain.index import BlockIndex
from src.agent.exchange_storage import ExchangeStorage
from src.agent.request_cache import RequestCache


class ProtectSimpleAgent(BaseAgent):
    """The ProtectSimple agent only stores on the chain the hashes of the data that was exchanged
    instead of all blocks. This way an agent still cannot lie but the chains remain as small as
    possible. However that agent needs to keep track of which data was received with which block.
    This happens with the RequestStorage.
    """

    _type = "ProtectSimple"

    def __init__(self, *args, **kwargs):
        super(ProtectSimpleAgent, self).__init__(*args, **kwargs)
        self.ignore_list = []
        self.request_cache = RequestCache()
        self.exchange_storage = ExchangeStorage()

    def request_protect(self, partner=None):
        while partner is None or partner == self.get_info():
            partner = random.choice(self.agents)

        if self.request_cache.get(partner.address) is not None:
            self.logger.error('Request already open, ignoring request with %s', partner.address)
            print self.request_cache
            return
        if partner.address in self.ignore_list:
            return

        chain = self.database.get_chain(self.public_key)

        db = msg.Database(info=self.get_info().as_message(),
                          blocks=[block.as_message() for block in chain])
        self.request_cache.new(partner.address)
        self.com.send(partner.address, NewMessage(msg.PROTECT_CHAIN, db))
        self.logger.debug("[0] Requesting PROTECT with %s", partner.address)

    @MessageHandler(msg.PROTECT_CHAIN)
    def protect_chain(self, sender, body):
        if self.request_cache.get(sender) is not None:
            self.logger.error('Request already open, ignoring request from %s', sender)
            print self.request_cache
            self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))
            return

        if sender in self.ignore_list:
            self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))
            return

        chain = [Block.from_message(block) for block in body.blocks]

        if len(chain) == 0:
            print body
            self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))
            return

        self.request_cache.new(sender, chain)
        verification = self.verify_chain(chain)
        if verification:
            self.com.send(sender, NewMessage(msg.PROTECT_INDEX_REQUEST, msg.Empty()))
            # self.open_requests[sender] = {'index': partner_index}
            # self.logger.debug("[1] Requesting BLOCKS from %s", sender)
        else:
            self.ignore_list.append(sender)
            self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))

    @MessageHandler(msg.PROTECT_INDEX_REQUEST)
    def protect_index_request(self, sender, body):
        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return

        message = self.exchange_storage.as_message()
        self.com.send(sender, NewMessage(msg.PROTECT_INDEX_REPLY, message))

    @MessageHandler(msg.PROTECT_INDEX_REPLY)
    def protect_index_reply(self, sender, body):
        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return

        exchanges = ExchangeStorage.from_message(body)
        verification = self.verify_exchange(self.request_cache.get(sender).chain, exchanges)

        if verification:
            partner_index = BlockIndex()
            for block_hash, index in exchanges.exchanges.iteritems():
                partner_index = partner_index + index
            chain_index = BlockIndex.from_blocks(self.request_cache.get(sender).chain)
            partner_index = partner_index + chain_index
            own_index = BlockIndex.from_blocks(self.database.get_all_blocks())
            if len(partner_index.to_database_args()) == 0:
                self.logger.warning("empty index: %s", body)
            db = (partner_index - own_index).as_message()
            self.com.send(sender, NewMessage(msg.PROTECT_BLOCKS_REQUEST, db))
            self.request_cache.get(sender).index = partner_index
        else:
            self.ignore_list.append(sender)
            self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))

    @MessageHandler(msg.PROTECT_BLOCKS_REQUEST)
    def protect_blocks_request(self, sender, body):
        if self.request_cache.get(sender) is None:
            logging.error('No open reqest found for this agent')
            return

        index = BlockIndex.from_message(body)

        if len(index.to_database_args()) == 0:
            print body
            print "Index: ", index.to_database_args()
        self.request_cache.get(sender).transfer_up = index
        blocks = self.database.index(index)

        # send missing blocks immediately
        db = msg.Database(info=self.get_info().as_message(),
                          blocks=[block.as_message() for block in blocks])
        self.com.send(sender, NewMessage(msg.PROTECT_BLOCKS_REPLY, db))
        self.logger.debug("[2] Sending BLOCKS to %s", sender)

    @MessageHandler(msg.PROTECT_BLOCKS_REPLY)
    def protect_blocks_reply(self, sender, body):
        if self.request_cache.get(sender) is None:
            logging.error('No open reqest found for this agent')
            return

        blocks = [Block.from_message(block) for block in body.blocks]

        verification = self.verify_blocks(blocks)

        if verification:
            own_chain = self.database.get_chain(self.public_key)
            own_index = BlockIndex.from_blocks(self.database.get_all_blocks())
            partner_index = self.request_cache.get(sender).index
            transfer_down = (own_index - partner_index)
            self.request_cache.get(sender).transfer_down = transfer_down
            sub_database = self.database.index(transfer_down)
            db = msg.ChainAndBlocks(chain=[block.as_message() for block in own_chain],
                                    blocks=[block.as_message() for block in sub_database])
            self.com.send(sender, NewMessage(msg.PROTECT_CHAIN_BLOCKS, db))
            self.logger.debug("[3] Sending CHAIN AND BLOCKS to %s", sender)

    @MessageHandler(msg.PROTECT_CHAIN_BLOCKS)
    def proect_chain_blocks(self, sender, body):
        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return
        chain = [Block.from_message(block) for block in body.chain]
        blocks = [Block.from_message(block) for block in body.blocks]

        verification = self.verify_chain_and_blocks(blocks)
        transfer_down = BlockIndex.from_blocks(blocks)

        if verification:
            # now initiater needs to check that everything is in order
            # if everything checks out we can create a block
            partner = next((a for a in self.agents if a.address == sender), None)
            payload = {'transfer_up': self.request_cache.get(sender).transfer_up.db_pack(),
                       'transfer_down': transfer_down.db_pack()}
            new_block = self.block_factory.create_new(partner.public_key, payload=payload)
            self.com.send(partner.address, NewMessage(msg.PROTECT_BLOCK_PROPOSAL,
                                                      new_block.as_message()))
            self.exchange_storage.add_exchange(new_block,
                                               self.request_cache.get(sender).transfer_up)
            self.logger.debug("[4] Sending PROPOSAL to %s", sender)

    @MessageHandler(msg.PROTECT_BLOCK_PROPOSAL)
    def protect_block_proposal(self, sender, body):
        self.logger.debug("[5.0] Received PROPOSAL from %s", sender)
        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return
        # check the hash of the database and if correct
        block = Block.from_message(body)
        self.database.add(block)

        new_block = self.block_factory.create_linked(block)
        self.com.send(sender, NewMessage(msg.PROTECT_BLOCK_AGREEMENT, new_block.as_message()))
        self.exchange_storage.add_exchange(new_block,
                                           self.request_cache.get(sender).transfer_down)
        self.logger.debug("[5.1] will delete open request %s", sender)
        self.request_cache.remove(sender)
        self.logger.debug("[5] Sending AGREEMENT to %s", sender)

    @MessageHandler(msg.PROTECT_BLOCK_AGREEMENT)
    def protect_block_agreement(self, sender, body):
        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return
        block = Block.from_message(body)
        self.database.add(block)
        partner = next((a for a in self.agents if a.address == sender), None)
        self.request_interaction(partner)
        self.request_cache.remove(sender)   
        self.logger.debug("[6] Storing AGREEMENT from %s", sender)

    @MessageHandler(msg.PROTECT_REJECT)
    def protect_reject(self, sender, body):
        if self.request_cache.get(sender) is None:
            self.logger.error('No open reqest found for this agent')
            return
        self.request_cache.remove(sender)

    def step(self):

        self.request_protect()

    def verify_chain(self, chain):
        """Verifies the correctness of a chain received by another agent.

        Arguments:
            chain {[Block]} -- Agent's complete chain

        Returns:
            bool -- Outcome of the verification, True means correct, False means fraud
        """

        seq = [block.sequence_number for block in chain]
        if not Counter(seq) == Counter(range(1, max(seq)+1)):
            return False
        return True

    def verify_blocks(self, block):

        return True

    def verify_chain_and_blocks(self, blocks):
        return True

    def verify_exchange(self, chain, exchange):
        return True
