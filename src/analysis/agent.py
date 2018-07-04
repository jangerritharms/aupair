"""
Analysis part of the agent.
"""
import pickle
import logging

import src.communication.messages_pb2 as msg

from src.chain.block import Block
from src.agent.info import AgentInfo


class Agent:

    def __init__(self, info, blocks):
        self.info = info
        self.blocks = blocks

    @classmethod
    def from_file(cls, data_file):
        logging.debug('Opening file: %s', data_file)
        blocks = []
        info = []
        with open(data_file, 'rb') as f:
            database = msg.Database()
            database.ParseFromString(f.read())

        return cls(AgentInfo.from_message(database.info),
                   [Block.from_message(block) for block in database.blocks])

    def size_database(self):
        return len(self.blocks)

    def transactions_blocks(self):
        blocks = [block for block in self.blocks
                  if block.public_key == self.info.public_key.as_bin() and
                  block.transaction.get('up')]
        agreement = [block for tx in blocks for block in self.blocks
                     if (block.public_key == tx.link_public_key and
                         block.sequence_number == tx.link_sequence_number) or
                     (block.link_public_key == tx.public_key and
                      block.link_sequence_number == tx.sequence_number)]

        return len(agreement)

    def exchange_blocks(self):
        blocks = [block for block in self.blocks
                  if block.public_key == self.info.public_key.as_bin()
                  and block.transaction.get('transfer_down')]
        return len(blocks)

    def foreign_blocks(self):
        blocks = [block for block in self.blocks
                  if block.public_key != self.info.public_key.as_bin()]
        return len(blocks)
