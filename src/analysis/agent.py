"""
Analysis part of the agent.
"""
import pickle
import logging

from src.pyipv8.ipv8.attestation.trustchain.block import TrustChainBlock
from src.pyipv8.ipv8.messaging.deprecated.encoding import encode

class Agent:

    def __init__(self, public_key, blocks):
        self.public_key = public_key
        self.blocks = blocks

    @classmethod
    def from_file(cls, data_file):
        logging.debug('Opening file: %s', data_file)
        blocks = []
        info = []
        with open(data_file, 'r') as f:
            line = f.readline()
            info = line.split(' ')
            blocks = []
            for _ in range(int(info[1])):
                block_line = f.readline()
                block_data = block_line.split(' ')
                block_data[0] = encode(pickle.loads(block_data[0].decode('hex')))
                blocks.append(TrustChainBlock(block_data))

        return cls(info[0], blocks)

    def size_database(self):
        return len(self.blocks)

    def transactions_blocks(self):
        blocks = [block for block in self.blocks if block.public_key == self.public_key and block.transaction.get('up')]
        return len(blocks)

    def exchange_blocks(self):
        blocks = [block for block in self.blocks if block.public_key == self.public_key and block.transaction.get('transfer_down')]
        return len(blocks)

    def foreign_blocks(self):
        blocks = [block for block in self.blocks if block.public_key != self.public_key]
        return len(blocks)
