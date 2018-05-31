"""Module defining the BlockFactory class.
"""
from src.chain.block import Block, GENESIS_HASH, UNKNOWN_SEQ

DUMMY_PAYLOAD = {"up": 10, "down": 10}


class BlockFactory(object):
    """The BlockFactory class is a convenience class for creating, signing and
    storing TrustChainBlocks.
    """

    def __init__(self, db, public_key, private_key):
        """Creates a new BlockFactory for an agent.

        Arguments:
            db {Database} -- Database of the owner agent
            public_key {PublicKey} -- Public key of the owner agent
            private_key {PrivateKey} -- Private key of the owner agent, for signing blocks
        """

        self.db = db
        self.public_key = public_key
        self.private_key = private_key

    def create_genesis(self):
        """Create the genesis block for an agent and store it in the database.
        """

        genesis_block = Block()
        genesis_block.public_key = self.public_key.as_bin()
        genesis_block.sign(self.private_key)
        self.db.add_block(genesis_block)

    def create_new(self, partner, payload=DUMMY_PAYLOAD):
        """Creates, signs and stores a new block proposal with the given payload.

        Arguments:
            payload {dict} -- Application specific payload for the transaction block
        """

        new_block = Block.create(payload,
                                 self.db,
                                 self.public_key.as_bin(),
                                 link_pk=partner.as_bin())
        new_block.sign(self.private_key)
        self.db.add(new_block)

        return new_block

    def create_linked(self, linked_block):
        """Creates, signs and stores a block confirmation for the given block proposal.

        Arguments:
            linked_block {TrustChainBlock} -- Block proposal to be confirmed.
        """

        new_block = Block.create(None,
                                 self.db,
                                 self.public_key.as_bin(),
                                 link=linked_block)
        new_block.sign(self.private_key)
        self.db.add(new_block)

        return new_block
