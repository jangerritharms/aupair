import random

import src.communication.messages_pb2 as msg

from src.agent.base import BaseAgent
from src.chain.block import Block
from src.communication.messaging import MessageHandler
from src.communication.messages import NewMessage


class ProtectAgent(BaseAgent):

    def request_protect(self, partner=None):

        while partner is None or partner == self.get_info():
            partner = random.choice(self.agents)

        # get chain and convert to database
        db = msg.Database(info=self.get_info().as_message(), blocks=[])
        self.com.send(partner.address, NewMessage(msg.PROTECT_CHAIN, db))

    @MessageHandler(msg.PROTECT_CHAIN)
    def protect_chain(self, sender, body):

        # obtain chain from payload, verify it and send back message with missing blocks
        db = msg.BlockIndex(entries=[])
        self.com.send(sender, NewMessage(msg.PROTECT_BLOCKS_REQUEST, db))

    @MessageHandler(msg.PROTECT_BLOCKS_REQUEST)
    def protect_blocks_request(self, sender, body):

        # send missing blocks immediately 
        db = msg.Database(info=self.get_info().as_message(), blocks=[])
        self.com.send(sender, NewMessage(msg.PROTECT_BLOCKS_REPLY, db))

    @MessageHandler(msg.PROTECT_BLOCKS_REPLY)
    def protect_blocks_reply(self, sender, body):

        # verify again that blocks are in order, no double-spend etc.
        # if verification succeeds, send chain and missing blocks
        db = msg.Database(info=self.get_info().as_message(), blocks=[])
        self.com.send(sender, NewMessage(msg.PROTECT_CHAIN_BLOCKS, db))

    @MessageHandler(msg.PROTECT_CHAIN_BLOCKS)
    def proect_chain_blocks(self, sender, body):

        # now initiater needs to check that everything is in order
        # if everything checks out we can create a block
        partner = next((a for a in self.agents if a.address == sender), None)
        new_block = self.block_factory.create_new(partner.public_key)
        self.com.send(partner.address, NewMessage(msg.PROTECT_BLOCK_PROPOSAL,
                                                  new_block.as_message()))

    @MessageHandler(msg.PROTECT_BLOCK_PROPOSAL)
    def protect_block_proposal(self, sender, body):

        # check the hash of the database and if correct 
        block = Block.from_message(body)
        self.database.add(block)

        new_block = self.block_factory.create_linked(block)
        self.com.send(sender, NewMessage(msg.BLOCK_AGREEMENT, new_block.as_message()))

    @MessageHandler(msg.PROTECT_BLOCK_AGREEMENT)
    def protect_block_agreement(self, sender, body):

        block = Block.from_message(body)
        self.database.add(block)
        partner = next((a for a in self.agents if a.address == sender), None)
        self.request_interaction(partner)

    def step(self):

        self.request_protect()
