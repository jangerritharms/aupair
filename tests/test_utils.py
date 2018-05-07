import unittest
import time
import os
import json

from src.pyipv8.ipv8.keyvault.crypto import ECCrypto
from src.pyipv8.ipv8.messaging.deprecated.encoding import encode
from src.pyipv8.ipv8.attestation.trustchain.block import TrustChainBlock, UNKNOWN_SEQ, EMPTY_SIG, GENESIS_HASH
from src.utils import create_index, calculate_difference
from src.agent import Agent

TEST_OPTIONS = {
    "emulation_duration": 0,
    "emulation_step_length": 0,
    "discovery_server_port": 0
}

class TestUtil(unittest.TestCase):

    def setUp(self):
        private_key_A = ECCrypto().generate_key('curve25519')
        self.key_A = private_key_A.pub().key_to_bin()
        private_key_B = ECCrypto().generate_key('curve25519')
        self.key_B = private_key_B.pub().key_to_bin()
        private_key_C = ECCrypto().generate_key('curve25519')
        self.key_C = private_key_C.pub().key_to_bin()
        self.chain = [TrustChainBlock()]
        self.database = [TrustChainBlock()]
        block_data = TrustChainBlock([encode({'up': 10, 'down': 10}),
                                      self.key_A,
                                      2,
                                      self.key_B,
                                      UNKNOWN_SEQ,
                                      GENESIS_HASH,
                                      EMPTY_SIG,
                                      time.time()])
        block_data.sign(private_key_A)
        self.chain.append(block_data)
        self.database.append(block_data)

        block_data = TrustChainBlock([encode({'up': 10, 'down': 10}),
                                      self.key_B,
                                      2,
                                      self.key_A,
                                      2,
                                      GENESIS_HASH,
                                      EMPTY_SIG,
                                      time.time()])
        self.database.append(block_data)

        block_data = TrustChainBlock([encode({'transfer_up': [[self.key_A, [2, 3]]],
                                       'transfer_down': [[self.key_B, [2, 3]]]}),
                                      self.key_A,
                                      3,
                                      self.key_B,
                                      UNKNOWN_SEQ,
                                      GENESIS_HASH,
                                      EMPTY_SIG,
                                      time.time()])
        self.database.append(block_data)
        self.chain.append(block_data)

        block_data = TrustChainBlock([encode({'transfer_up': [[self.key_A, [2]]],
                                       'transfer_down': [[self.key_B, [2]]]}),
                                      self.key_B,
                                      3,
                                      self.key_A,
                                      3,
                                      GENESIS_HASH,
                                      EMPTY_SIG,
                                      time.time()])
        self.database.append(block_data)

        # B interacts twice with C

        block_data = TrustChainBlock([encode({'transfer_up': [[self.key_C, [1, 2, 3, 4]],[self.key_B, [4, 5, 6]]],
                                       'transfer_down': []}),
                                      self.key_B,
                                      5,
                                      self.key_A,
                                      UNKNOWN_SEQ,
                                      GENESIS_HASH,
                                      EMPTY_SIG,
                                      time.time()])
        self.database.append(block_data)

        block_data = TrustChainBlock([encode({'transfer_up': [[self.key_C, [1, 2, 3, 4]],[self.key_B, [4, 5, 6]]],
                                       'transfer_down': []}),
                                      self.key_A,
                                      4,
                                      self.key_B,
                                      5,
                                      GENESIS_HASH,
                                      EMPTY_SIG,
                                      time.time()])
        self.chain.append(block_data)
        self.database.append(block_data)


    def test1(self):
        "Creates the correct index for agent A."
        index = create_index(self.chain, self.key_A)
        
        self.assertTrue([self.key_A, [1, 2, 3, 4]] in index)
        self.assertTrue([self.key_B, [2, 3, 4, 5, 6]] in index)
        self.assertTrue([self.key_C, [1, 2, 3, 4]] in index)

    def test2(self):
        "Creates the correct difference between agents for agent A."
        indexA = [[self.key_A, [1, 2, 3, 4]], [self.key_B, [2, 3, 4, 5, 6]]]
        indexB = [[self.key_B, [1, 2, 3, 4, 5, 6, 7]],
                  [self.key_A, [1, 2]],
                  [self.key_C, [1, 2, 3]]]

        difference = calculate_difference(indexA, indexB)
        self.assertTrue([self.key_A, [3, 4]] in difference)

    def test3(self):
        "Creates the correct difference between agents for agent B."
        indexA = [[self.key_A, [1, 2, 3, 4]], [self.key_B, [2, 3, 4, 5, 6]]]
        indexB = [[self.key_B, [1, 2, 3, 4, 5, 6, 7]],
                  [self.key_A, [1, 2]],
                  [self.key_C, [1, 2, 3]]]

        difference = calculate_difference(indexB, indexA)
        self.assertTrue([self.key_B, [1, 7]] in difference)
        self.assertTrue([self.key_C, [1, 2, 3]] in difference)

