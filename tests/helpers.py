import src.communication.messages_pb2 as msg
import pickle

from src.pyipv8.ipv8.keyvault.crypto import ECCrypto
from src.pyipv8.ipv8.attestation.trustchain.block import GENESIS_HASH, EMPTY_SIG
from src.pyipv8.ipv8.messaging.deprecated.encoding import encode
from src.public_key import PublicKey
from src.chain.block import Block

TEST_SK = ECCrypto().generate_key('curve25519')
TEST_PK = PublicKey(TEST_SK.pub())


def generate_key():
    sk = ECCrypto().generate_key('curve25519')
    return sk.pub().key_to_bin()


class MockObject(object):
    pass


class MockBlockGenerator(object):

    def __init__(self):
        self.public_key = generate_key()
        self.generated = []

    def generate_simple(self):
        block = MockObject()
        block.public_key = self.public_key
        block.sequence_number = len(self.generated)+1
        block.transaction = {'up': 10}
        self.generated.append(block)
        return block

    def generate_simple_with_payload(self, payload):
        block = MockObject()
        block.public_key = self.public_key
        block.sequence_number = len(self.generated)+1
        block.transaction = payload
        self.generated.append(block)
        return block
    
    def generate_db(self):
        data = (
            buffer(encode({"up": 10})),
            buffer(self.public_key),
            len(self.generated)+1,
            buffer(generate_key()),
            -1,
            buffer(GENESIS_HASH),
            buffer(EMPTY_SIG),
            buffer(GENESIS_HASH)
        )
        block = MockObject()
        block.pack_db_insert = lambda: data

        self.generated.append(block)
        return block

    def generate_message(self):
        block = MockObject()
        block.as_message = lambda: msg.Block(
            payload=pickle.dumps({"up": 10}),
            public_key=self.public_key,
            sequence_number=len(self.generated)+1,
            link_public_key=generate_key(),
            link_sequence_number=-1,
            previous_hash=GENESIS_HASH,
            signature=EMPTY_SIG
        )
        return block