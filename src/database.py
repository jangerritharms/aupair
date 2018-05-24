"""
Module defining the database class.
"""
import logging

from src.pyipv8.ipv8.database import sqlite3
from src.pyipv8.ipv8.attestation.trustchain.database import TrustChainDB

class Database(TrustChainDB):
    """An extension of the general TrustChainDB database interface. This class provides additional
    security checks, deletion for creating double-spending attacks and some convenience methods.
    """

    def __init__(self, *args):
        """
        Initializes new database.
        """
        super(Database, self).__init__(*args)

    def add(self, block, check_double_spend=False):
        """
        Adds a block to the database.
        """
        try:
            self.add_block(block)
        except sqlite3.IntegrityError:
            logging.warning('Error adding block %s', block)

            if check_double_spend:
                existing = self.database.get(block.public_key, block.sequence_number)
                if existing.hash != block.hash:
                    logging.warning('DOUBLE SPENDING DETECTED after %d seconds', self.start_time - time.time())

    def get_chain(self, key):
        """Retrives the chain (all blocks authored) of the agent with the given
        public key.
        
        Arguments:
            key {PublicKey} -- Public key of the agent for which the chain is retrieved.

        Returns:
            {[TrustChainBlock]} -- List of blocks, ordered by sequence number.
        """
        return self.database._getall('WHERE public_key = ?', (buffer(key.key_to_bin()),))

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

        self.database.execute(
                        'DELETE FROM blocks WHERE public_key = ? AND sequence_number >= ? ' + \
                        'AND sequence_number < ?',
                        (buffer(key.key_to_bin()),
                        sequence_begin,
                        sequence_begin + sequence_length))
    