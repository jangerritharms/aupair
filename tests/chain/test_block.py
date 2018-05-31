import unittest

from src.chain.block import Block
from tests.helpers import generate_key


class TestBlock(unittest.TestCase):

    def test1(self):
        "can be converted to a message"
        block = Block()

        block_msg = block.as_message()
        self.assertEqual(block_msg.sequence_number, block.sequence_number)
        self.assertEqual(block_msg.public_key, block.public_key)

    def test2(self):
        "can be reconverted back to same block"
        block = Block()
        block_msg = block.as_message()
        block2 = Block.from_message(block_msg)

        self.assertEqual(block, block2)
