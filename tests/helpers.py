from src.pyipv8.ipv8.keyvault.crypto import ECCrypto
from src.agent import PublicKey

TEST_SK= ECCrypto().generate_key('curve25519')
TEST_PK = PublicKey(TEST_SK.pub())