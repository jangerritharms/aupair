"""
Module defining the database class.
"""

class Database:
    """
    Simplified memory version of database.
    """

    def __init__(self):
        """
        Initializes new database.
        """
        self.blocks = []


    def get_latest(self, public_key):
        """
        Returns the latest known block of the agent with the given public key.
        """
        latest = None 
        for block in self.blocks:
            if block.public_key == public_key:
                if latest is None or block.sequence_number > latest.sequence_number:
                    latest = block

        return latest


    def add(self, block):
        """
        Adds a block to the database.
        """
        self.blocks.append(block)
