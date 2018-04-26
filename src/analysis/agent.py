"""
Analysis part of the agent.
"""

from src.pyipv8.ipv8.attestation.trustchain.block import TrustChainBlock

class Agent:

    def __init__(self, public_key, blocks):
        self.blocks = blocks

    @classmethod
    def from_file(cls, data_file):
        blocks = []
        info = []
        with open(data_file, 'r') as f:
            line = f.readline()
            info = line.split(' ')
            blocks = []
            for _ in range(int(info[1])):
                block_line = f.readline()
                blocks.append(TrustChainBlock(block_line.split(' ')))

        return cls(info[0], blocks)

    def size_database(self):
        return len(self.blocks)
