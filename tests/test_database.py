import unittest
import os

from src.database import Database
from tests.helpers import MockBlockGenerator, MockObject


class TestDatabase(unittest.TestCase):

    def setUp(self):
        self.database = Database('tests', 'test')

    def tearDown(self):
        self.database.close()

        files = os.listdir('sqlite/')
        for db_file in files:
            file_path = os.path.join('sqlite', db_file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(e)

    def test1(self):
        "can obtain the chain only"
        generator = MockBlockGenerator()
        generator_b = MockBlockGenerator()
        self.database = Database('', 'test')
        self.database.add_block(generator.generate_db())
        self.database.add_block(generator.generate_db())
        self.database.add_block(generator_b.generate_db())
        self.database.add_block(generator_b.generate_db())

        pk = MockObject()
        pk.as_buffer = lambda: buffer(generator.public_key)
        chain = self.database.get_chain(pk)

        self.assertEqual(len(chain), 2)

    def test2(self):
        "can obtain block by index"
        generator = MockBlockGenerator()
        generator_b = MockBlockGenerator()
        self.database = Database('', 'test')
        block_a = generator.generate_db()
        self.database.add_block(block_a)
        self.database.add_block(generator.generate_db())
        self.database.add_block(generator_b.generate_db())
        block_b = generator_b.generate_db()
        self.database.add_block(block_b)

        index = MockObject()
        index.to_database_args = lambda: [(generator.public_key, 1), (generator_b.public_key, 2)]
        blocks = self.database.index(index)

        self.assertEqual(len(blocks), 2)
        self.assertTrue(blocks[0].public_key == generator.public_key)
        self.assertEqual(blocks[0].sequence_number, 1)
        self.assertTrue(blocks[1].public_key == generator_b.public_key)
        self.assertEqual(blocks[1].sequence_number, 2)
