from src.pyipv8.ipv8.keyvault.crypto import ECCrypto
from src.public_key import PublicKey

TEST_SK= ECCrypto().generate_key('curve25519')
TEST_PK = PublicKey(TEST_SK.pub())


def generate_key():
    sk = ECCrypto().generate_key('curve25519')
    return PublicKey(sk.pub())