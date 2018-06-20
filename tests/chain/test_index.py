import unittest

from src.chain.index import BlockIndex, UNKNOWN_SEQ, msg
from tests.helpers import MockObject, MockBlockGenerator, generate_key


class TestBlockIndex(unittest.TestCase):

    def test1(self):
        "can calculate correct index given some blocks"
        blocks = []

        gen_a = MockBlockGenerator()
        blocks.append(gen_a.generate_simple())
        blocks.append(gen_a.generate_simple())
        blocks.append(gen_a.generate_simple())
        gen_b = MockBlockGenerator()
        blocks.append(gen_b.generate_simple())
        blocks.append(gen_b.generate_simple())

        index = BlockIndex.from_blocks(blocks)

        self.assertEqual(len(index.entries), 2)
        index_a = dict(index.entries).get(gen_a.public_key)
        self.assertNotEqual(index_a, None)
        self.assertEqual(index_a, range(1, 4))
        index_b = dict(index.entries).get(gen_b.public_key)
        self.assertNotEqual(index_b, None)
        self.assertEqual(index_b, range(1, 3))

    def test2(self):
        "can calculate index from chain"
        key_b = generate_key()
        key_c = generate_key()
        gen_a = MockBlockGenerator()
        blocks = []
        blocks.append(gen_a.generate_simple())
        blocks.append(gen_a.generate_simple())
        blocks.append(gen_a.generate_simple())
        transfer_block = gen_a.generate_simple_with_payload({
            'transfer_up': [(key_b.encode('hex'), [1, 2, 3])],
            'transfer_down': [(key_c.encode('hex'), [2, 3, 4])]})
        transfer_block.link_sequence_number = UNKNOWN_SEQ
        blocks.append(transfer_block)
        transfer_block = gen_a.generate_simple_with_payload({
            'transfer_up': [(key_b.encode('hex'), [4, 5, 6])],
            'transfer_down': [(key_c.encode('hex'), [1, 2])]})
        transfer_block.link_sequence_number = 10
        blocks.append(transfer_block)

        index = BlockIndex.from_chain(blocks)

        self.assertEqual(len(index.entries), 3)
        index_a = dict(index.entries).get(gen_a.public_key)
        self.assertNotEqual(index_a, None)
        self.assertEqual(index_a, range(1, 6))
        index_b = dict(index.entries).get(key_b)
        self.assertNotEqual(index_b, None)
        self.assertEqual(index_b, range(4, 7))
        index_c = dict(index.entries).get(key_c)
        self.assertNotEqual(index_c, None)
        self.assertEqual(index_c, range(2, 5))

    def test3(self):
        "can export as database args"
        key_a = generate_key()
        key_b = generate_key()

        index = BlockIndex([(key_a, [1, 2, 3, 4]), (key_b, [12])])
        args = index.to_database_args()

        self.assertEqual(args, [(key_a, 1), (key_a, 2), (key_a, 3), (key_a, 4),
                                (key_b, 12)])

    def test4(self):
        "can subtract two indices"
        key_a = generate_key()
        key_b = generate_key()
        key_c = generate_key()

        index = BlockIndex([(key_a, [1, 2, 3, 4]), (key_b, [12])])
        partner_index = BlockIndex([(key_a, [1, 2]), (key_c, [12])])

        sub1 = index - partner_index
        self.assertEqual(type(sub1), BlockIndex)
        self.assertEqual(len(sub1.entries), 2)
        index_a = dict(sub1.entries).get(key_a)
        self.assertNotEqual(index_a, None)
        self.assertEqual(index_a, range(3, 5))
        index_b = dict(sub1.entries).get(key_b)
        self.assertNotEqual(index_b, None)
        self.assertEqual(index_b, range(12, 13))

    def test5(self):
        "can create a database index message"
        key_a = generate_key()
        key_b = generate_key()
        index = BlockIndex([(key_a, [1, 2, 3, 4]), (key_b, [12])])

        message = index.as_message()

        self.assertEqual(type(message), msg.BlockIndex)
        self.assertEqual(len(message.entries), 2)

    def test6(self):
        "can add two indices"
        key_a = generate_key()
        key_b = generate_key()
        key_c = generate_key()

        index = BlockIndex([(key_a, [1, 2, 3, 4]), (key_b, [12])])
        partner_index = BlockIndex([(key_a, [1, 2]), (key_c, [12])])

        add1 = index + partner_index
        self.assertEqual(type(add1), BlockIndex)
        self.assertEqual(len(add1.entries), 3)
        index_a = dict(add1.entries).get(key_a)
        self.assertNotEqual(index_a, None)
        self.assertEqual(index_a, range(1, 5))
        index_b = dict(add1.entries).get(key_b)
        self.assertNotEqual(index_b, None)
        self.assertEqual(index_b, range(12, 13))
        index_c = dict(add1.entries).get(key_c)
        self.assertNotEqual(index_c, None)
        self.assertEqual(index_c, range(12, 13))

    def test7(self):
        "can add an empty with a non-empty index"
        key_a = generate_key()
        key_b = generate_key()
        key_c = generate_key()

        add1 = BlockIndex()
        partner_index = BlockIndex([(key_a, [1])])

        add1 += partner_index
        self.assertEqual(type(add1), BlockIndex)
        self.assertEqual(len(add1.entries), 1)
        index_a = dict(add1.entries).get(key_a)
        self.assertNotEqual(index_a, None)
        self.assertEqual(index_a, range(1, 2))

    def test8(self):
        "can add two of the same index"
        key_a = generate_key()
        key_b = generate_key()
        key_c = generate_key()

        index = BlockIndex([(key_a, [1, 2]), (key_c, [12])])
        partner_index = BlockIndex([(key_a, [1, 2]), (key_c, [12])])

        add1 = partner_index + index
        self.assertEqual(type(add1), BlockIndex)
        self.assertEqual(len(add1.entries), 2)
        index_a = dict(add1.entries).get(key_a)
        self.assertNotEqual(index_a, None)
        self.assertEqual(index_a, range(1, 3))
        index_c = dict(add1.entries).get(key_c)
        self.assertNotEqual(index_c, None)
        self.assertEqual(index_c, range(12, 13))