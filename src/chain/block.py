import pickle
import time

import src.communication.messages_pb2 as msg

from src.pyipv8.ipv8.attestation.trustchain.block import TrustChainBlock, GENESIS_HASH, EMPTY_SIG, \
    EMPTY_PK, GENESIS_SEQ, UNKNOWN_SEQ
from src.pyipv8.ipv8.messaging.serialization import Serializer


class Block(TrustChainBlock):
    """Extension to the normal TrustChainBlock, mostly for convenience to conver blocks to
    messages and back.
    """

    def __init__(self, data=None, serializer=Serializer()):
        if data is None:
            # data
            self.transaction = {}
            # identity
            self.public_key = EMPTY_PK
            self.sequence_number = GENESIS_SEQ
            # linked identity
            self.link_public_key = EMPTY_PK
            self.link_sequence_number = UNKNOWN_SEQ
            # validation
            self.previous_hash = GENESIS_HASH
            self.signature = EMPTY_SIG
            # debug stuff
            self.insert_time = None
        else:
            self.transaction = data[0]
            (self.public_key, self.sequence_number, self.link_public_key, self.link_sequence_number,
             self.previous_hash, self.signature, self.insert_time) = (
                data[1], data[2], data[3], data[4], data[5], data[6], data[7])
            if isinstance(self.public_key, buffer):
                self.public_key = str(self.public_key)
            if isinstance(self.link_public_key, buffer):
                self.link_public_key = str(self.link_public_key)
            if isinstance(self.previous_hash, buffer):
                self.previous_hash = str(self.previous_hash)
            if isinstance(self.signature, buffer):
                self.signature = str(self.signature)
        self.serializer = serializer

    def as_message(self):
        """Convert a Block to a message to send to other agents.

        Returns:
            msg.Block -- Block message describing the block instance.
        """
        return msg.Block(
            payload=pickle.dumps(self.transaction),
            public_key=self.public_key,
            sequence_number=self.sequence_number,
            link_public_key=self.link_public_key,
            link_sequence_number=self.link_sequence_number,
            previous_hash=self.previous_hash,
            signature=self.signature,
            insert_time=str(self.insert_time)
        )

    @classmethod
    def from_message(cls, message):
        """Creats a block from a block message.

        Arguments:
            message {msg.Block} -- Block message describing the block to be created.
        """

        return cls([
            pickle.loads(message.payload),
            message.public_key,
            message.sequence_number,
            message.link_public_key,
            message.link_sequence_number,
            message.previous_hash,
            message.signature,
            message.insert_time
        ])

    @classmethod
    def convert_to_Block(cls, obj):
        """Converts TrustChainBlocks to Blocks.
   
        Arguments:
            obj {TrustChainBlock} -- Block that will be converted
        """

        obj.__class__ = Block
        return obj

    def is_transaction(self):
        """Looks at the data stored in the transaction field and determines whether the block is a
        transaction or not. For this usecase transactions contain the "up" and "down" field.
        """
        return self.transaction.get('up') is not None and self.transaction.get('down') is not None

    def is_double_exchange(self):
        """Looks at the data stored in the transaction field and determines whether the block is a
        transaction or not. For this usecase transactions contain the "up" and "down" field.
        """
        return self.transaction.get('transfer_down') is not None and \
            self.transaction.get('transfer_up') is not None

    def is_single_exchange(self):
        """Looks at the data stored in the transaction field and determines whether the block is a
        transaction or not. For this usecase transactions contain the "up" and "down" field.
        """
        return self.transaction.get('transfer_down') is not None and \
            self.transaction.get('transfer_up') is None

    def is_exchange(self):
        """Looks at the data stored in the transaction field and determines whether the block is an
        exchange or not. For this usecase exchanges contain the "transfer_down" field.
        """
        return self.transaction.get('transfer_down')

    def get_relevant_exchange(self):
        """If the agent mentioned in public_key field is requester, the relevant exchange is what 
        the agent downloaded, so "transfer_down", in that case the link_sequence_number is equal to 
        UNKNOWN_SEQ. Otherwise the relevant exchange is "transfer_up".
        """
        if not self.is_exchange():
            raise Exception("Block is not an exchange block and therefore has no relevant exchange")

        return self.transaction['transfer_down'] if self.link_sequence_number == UNKNOWN_SEQ \
            else self.transaction['transfer_up']

    def get_relevant_chain_length(self):
        """Transfer blocks also record the chain of both parties shared up to that point.
        """
        if not self.is_double_exchange():
            raise Exception("Block is not a double exchange block and therefore has no relevant\
            chain length")

        return self.transaction['chain_down'] if self.link_sequence_number == UNKNOWN_SEQ \
            else self.transaction['chain_up']
