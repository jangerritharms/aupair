import random
import logging

import src.communication.messages_pb2 as msg

from src.agent.base import BaseAgent
from src.chain.block import Block
from src.communication.messaging import MessageHandler
from src.communication.messages import NewMessage
from src.chain.index import BlockIndex


class ProtectAgent(BaseAgent):

    def __init__(self, *args, **kwargs):
        super(ProtectAgent, self).__init__(*args, **kwargs)
        self.ignore_list = []
        self.open_requests = {}

    def request_protect(self, partner=None):
        tries = 0
        while partner is None or partner == self.get_info() or \
                partner.address in self.open_requests:
            if tries > len(self.agents):
                return
            partner = random.choice(self.agents)
            tries += 1

        chain = self.database.get_chain(self.public_key)
        db = msg.Database(info=self.get_info().as_message(),
                          blocks=[block.as_message() for block in chain])
        self.open_requests[partner.address] = {}
        self.com.send(partner.address, NewMessage(msg.PROTECT_CHAIN, db))
        self.logger.debug("[0] Requesting PROTECT with %s", partner.address)

    @MessageHandler(msg.PROTECT_CHAIN)
    def protect_chain(self, sender, body):
        if self.open_requests.get(sender) is not None:
            logging.error('Request already open, ignoring')
            self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))
            return
        chain = [Block.from_message(block) for block in body.blocks]

        verification = self.verify_chain(chain)
        if verification:
            partner_index = BlockIndex.from_chain(chain)
            own_index = BlockIndex.from_chain(self.database.get_chain(self.public_key))
            db = (partner_index - own_index).as_message()
            self.com.send(sender, NewMessage(msg.PROTECT_BLOCKS_REQUEST, db))
            self.open_requests[sender] = {'index': partner_index}
            self.logger.debug("[1] Requesting BLOCKS from %s", sender)
        else:
            ignore_list.append(AgentInfo.from_message(body.info))

    @MessageHandler(msg.PROTECT_BLOCKS_REQUEST)
    def protect_blocks_request(self, sender, body):
        index = BlockIndex.from_message(body)

        self.open_requests[sender]['transfer_up'] = index
        blocks = self.database.index(index)
        # send missing blocks immediately
        db = msg.Database(info=self.get_info().as_message(),
                          blocks=[block.as_message() for block in blocks])
        self.com.send(sender, NewMessage(msg.PROTECT_BLOCKS_REPLY, db))
        self.logger.debug("[2] Sending BLOCKS to %s", sender)

    @MessageHandler(msg.PROTECT_BLOCKS_REPLY)
    def protect_blocks_reply(self, sender, body):
        if self.open_requests.get(sender) is None:
            logging.error('No open reqest found for this agent')
            return

        blocks = [Block.from_message(block) for block in body.blocks]

        verification = self.verify_blocks(blocks)

        if verification:
            # verify again that blocks are in order, no double-spend etc.
            # if verification succeeds, send chain and missing blocks
            own_chain = self.database.get_chain(self.public_key)
            own_index = BlockIndex.from_chain(own_chain)
            partner_index = self.open_requests[sender]['index']
            dif = (own_index - partner_index)
            sub_database = self.database.index(dif)
            db = msg.ChainAndBlocks(chain=[block.as_message() for block in own_chain],
                                    blocks=[block.as_message() for block in sub_database])
            self.com.send(sender, NewMessage(msg.PROTECT_CHAIN_BLOCKS, db))
            self.logger.debug("[3] Sending CHAIN AND BLOCKS to %s", sender)

    @MessageHandler(msg.PROTECT_CHAIN_BLOCKS)
    def proect_chain_blocks(self, sender, body):
        if self.open_requests.get(sender) is None:
            logging.error('No open reqest found for this agent')
            return
        chain = [Block.from_message(block) for block in body.chain]
        blocks = [Block.from_message(block) for block in body.blocks]

        verification = self.verify_chain_and_blocks(blocks)
        transfer_down = BlockIndex.from_blocks(blocks)

        if verification:
            # now initiater needs to check that everything is in order
            # if everything checks out we can create a block
            partner = next((a for a in self.agents if a.address == sender), None)
            payload = {'transfer_up': self.open_requests[sender]['transfer_up'].db_pack(),
                       'transfer_down': transfer_down.db_pack()}
            new_block = self.block_factory.create_new(partner.public_key, payload=payload)
            self.com.send(partner.address, NewMessage(msg.PROTECT_BLOCK_PROPOSAL,
                                                      new_block.as_message()))
            self.logger.debug("[4] Sending PROPOSAL to %s", sender)

    @MessageHandler(msg.PROTECT_BLOCK_PROPOSAL)
    def protect_block_proposal(self, sender, body):
        self.logger.debug("[5.0] Received PROPOSAL from %s", sender)
        if self.open_requests.get(sender) is None:
            logging.error('No open reqest found for this agent')
            return
        # check the hash of the database and if correct
        block = Block.from_message(body)
        self.database.add(block)

        new_block = self.block_factory.create_linked(block)
        self.com.send(sender, NewMessage(msg.PROTECT_BLOCK_AGREEMENT, new_block.as_message()))
        self.logger.debug("[5.1] will delete open request %s", sender)
        del self.open_requests[sender]
        self.logger.debug("[5] Sending AGREEMENT to %s", sender)

    @MessageHandler(msg.PROTECT_BLOCK_AGREEMENT)
    def protect_block_agreement(self, sender, body):
        if self.open_requests.get(sender) is None:
            logging.error('No open reqest found for this agent')
            return
        block = Block.from_message(body)
        self.database.add(block)
        partner = next((a for a in self.agents if a.address == sender), None)
        self.request_interaction(partner)
        del self.open_requests[sender]
        self.logger.debug("[6] Storing AGREEMENT from %s", sender)

    @MessageHandler(msg.PROTECT_REJECT)
    def protect_reject(self, sender, body):
        if self.open_requests.get(sender) is None:
            logging.error('No open reqest found for this agent')
            return
        del self.open_requests[sender]

    def step(self):

        self.request_protect()

    def verify_chain(self, chain):
        """Verifies the correctness of a chain received by another agent.

        Arguments:
            chain {[Block]} -- Agent's complete chain

        Returns:
            bool -- Outcome of the verification, True means correct, False means fraud
        """

        return True

    def verify_blocks(self, block):

        return True

    def verify_chain_and_blocks(self, blocks):
        return True