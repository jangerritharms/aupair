"""
Module defining the database class.
"""
import logging

from src.pyipv8.ipv8.database import sqlite3
from src.pyipv8.ipv8.attestation.trustchain.database import TrustChainDB
from src.chain.block import Block


class Database(TrustChainDB):
    """An extension of the general TrustChainDB database interface. This class provides additional
    security checks, deletion for creating double-spending attacks and some convenience methods.
    """

    def __init__(self, *args):
        """
        Initializes new database.
        """
        super(Database, self).__init__(*args)

    def _getall(self, *args, **kwargs):
        trust_chain_blocks = super(Database, self)._getall(*args, **kwargs)
        return [Block.convert_to_Block(block) for block in trust_chain_blocks]

    def add(self, block, check_double_spend=True):
        """
        Adds a block to the database.
        """
        try:
            self.add_block(block)
        except sqlite3.IntegrityError:
            if check_double_spend:
                existing = self.get(block.public_key, block.sequence_number)
                if existing.hash != block.hash:
                    logging.warning('DOUBLE SPENDING DETECTED at block %s', existing)
                    return existing
        return False

    def add_blocks(self, blocks, check_double_spend=True):
        """Addes multiple blocks to the database.
        
        Arguments:
            blocks {[Blocks]} -- Blocks to be added to the database.
        """

        for block in blocks:
            result = self.add(block, check_double_spend)

            if result != False:
                return result

        return False

    def get_chain(self, key):
        """Retrives the chain (all blocks authored) of the agent with the given
        public key.

        Arguments:
            key {PublicKey} -- Public key of the agent for which the chain is retrieved.

        Returns:
            {[TrustChainBlock]} -- List of blocks, ordered by sequence number.
        """
        return self._getall('WHERE public_key = ?', (key.as_buffer(),))

    def delete(self, key, sequence_begin, sequence_length=1):
        """Deletes a sequence of blocks from the database. This can be used as a simple way to
        create a double-spend attack, by removing a block from the end of the chain, a new block
        will reuse a previously used sequence number.

        Arguments:
            key {PublicKey} -- Public key of the agent whose chain will be altered
            sequence_begin {int} -- First sequence number to delete

        Keyword Arguments:
            sequence_length {int} -- Number of blocks to remove (default: {-1})
        """

        self.execute(
                    'DELETE FROM blocks WHERE public_key = ? AND sequence_number >= ? ' +
                    'AND sequence_number < ?',
                    (key.as_buffer(),
                        sequence_begin,
                        sequence_begin + sequence_length))

    def get_all_blocks(self):
        return self._getall('', ())

    def index(self, index):
        """Returns a subset of the database indexed by the passed index.

        Arguments:
            index {BlockIndex} -- Index, defining which subset of blocks to return.
        """

        args = index.to_database_args()
        db_args = []
        for arg in args:
            db_args.extend([buffer(arg[0]), arg[1]])
        query = 'WHERE (public_key, sequence_number) IN (VALUES {})'.format(
            ','.join(['(?,?)']*len(args)))
        return self._getall(query, tuple(db_args))

    def index_with_replacements(self, index, replacements):
        """Get blocks from the database with specific replacements in order to simulate another
        agent.
        
        Arguments:
            index {BlockIndex} -- Index, defining which subset of blocks to return
            replacements {[(Block, Block)]} -- List of tuples with first element the block to be
                replaced and the second element the block to fill in 
        """
        blocks = self.index(index)

        for block1, block2 in replacements:
            if block1 in blocks:
                blocks = [b if b.hash != block1.hash else block2 for b in blocks]
        
        return blocks