import unittest

from tests.helpers import TEST_SK
from src.public_key import PublicKey

class TestPublicKey(unittest.TestCase):

    def test1(self):
        "Create a public key"
        public_key = PublicKey(TEST_SK.pub)

    def test2(self):
        "Can export as binary string"
        public_key = PublicKey(TEST_SK.pub())
        bin_key = public_key.as_bin()

        self.assertEqual(type(bin_key), str)
        self.assertEqual(bin_key[:10], "LibNaCLPK:")

    def test3(self):
        "Can reimport exported bin public key"
        public_key = PublicKey(TEST_SK.pub())
        bin_key = public_key.as_bin()
        public_key2 = PublicKey.from_bin(bin_key)

        self.assertEqual(public_key.key.key_to_bin(), public_key2.key.key_to_bin())

    def test4(self):
        "Can reimport exported hex public key"
        public_key = PublicKey(TEST_SK.pub())
        bin_key = public_key.as_hex()
        public_key2 = PublicKey.from_hex(bin_key)

        self.assertEqual(public_key.key.key_to_bin(), public_key2.key.key_to_bin())

    def test5(self):
        "Two PublicKey objects are equal with same key"

        public_key = PublicKey(TEST_SK.pub())
        public_key2 = PublicKey(TEST_SK.pub())

        self.assertEqual(public_key, public_key2)
