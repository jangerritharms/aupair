import src.communication.messages_pb2 as msg
from src.pyipv8.ipv8.attestation.trustchain.block import UNKNOWN_SEQ


class BlockIndex(object):
    """The BlockIndex is one of the major components that enable the calculation of the state of the
    agent given their chain. The index shows for each public key, which blocks are recorded, either
    in an exchange or in the database itself. The entries of the index consists of tuples
    (public_key, [indices]), where the list of indices shows which sequence numbers of that public
    key are present. The sequence number given by "to" is also included in the range in contrast to
    the standard indexing in Python.
    """

    def __init__(self, entries=[]):
        """Creates a new BlockIndex and initializes the entries.

        Keyword Arguments:
            entries {[(PublicKey,[int])]} -- Initial entries of the BlockIndex
             (default: {[]})
        """

        self.entries = entries

    @classmethod
    def from_chain(cls, chain):
        """Calculates the index of a given chain.

        Arguments:
            chain {[Block]} -- Complete chain of another agent.
        """

        index_dict = {}
        for block in chain:
            index_dict.setdefault(block.public_key, []).append(block.sequence_number)
            if block.transaction.get('transfer_up') or block.transaction.get('transfer_down'):
                transfer = {}
                if block.link_sequence_number != UNKNOWN_SEQ:
                    transfer = block.transaction['transfer_up']
                else:
                    transfer = block.transaction['transfer_down']
                for elem in transfer:
                    index_dict.setdefault(elem[0].decode('hex'), []).extend(elem[1])

        return cls([(elem[0], sorted(list(set(elem[1])))) for elem in index_dict.items()])

    @classmethod
    def from_blocks(cls, blocks):
        """Calculates the index given all blocks that should be in the index e.g. from a database.

        Arguments:
            blocks {[Block]} -- All blocks that should be recorded in the index.
        """

        index_dict = {}
        for block in blocks:
            index_dict.setdefault(block.public_key, []).append(block.sequence_number)

        return cls([(elem[0], sorted(list(set(elem[1])))) for elem in index_dict.items()])

    @classmethod
    def from_message(cls, message):
        return cls([(entry.public_key, range(entry.begin, entry.end+1))
                    for entry in message.entries])

    def __sub__(self, other):
        """Returns an index of the items which are in self but not in other.

        Arguments:
            other {BlockIndex} -- The index which shall be subtracted
        """

        own_index = sorted(self.entries, key=lambda x: x[0])
        other_index = sorted(other.entries, key=lambda x: x[0])

        i = 0
        j = 0
        exchange = []
        while i < len(own_index) and j < len(other_index):
            own_key = own_index[i][0]
            other_key = other_index[j][0]

            if own_key == other_key:
                if own_index[i][1] != other_index[j][1]:
                    diff = list(set(own_index[i][1]) - set(other_index[j][1]))
                    if len(diff) > 0:
                        exchange.append((own_key, diff))
                i += 1
                j += 1
            elif own_key < other_key:
                exchange.append((own_key, own_index[i][1]))
                i += 1
            else:
                j += 1

        while i < len(own_index):
            own_key = own_index[i][0]
            exchange.append((own_key, own_index[i][1]))
            i += 1

        return BlockIndex(exchange)

    def as_message(self):
        """Creates a BlockIndex message from the given object.
        """
        message_entries = [msg.BlockIndexEntry(public_key=entry[0],
                                               begin=min(entry[1]),
                                               end=max(entry[1])) for entry in self.entries]
        return msg.BlockIndex(entries=message_entries)

    def to_database_args(self):
        """Converts the entries to tuples of (public_key, sequence_number) entries for each single
        block. This is a convenience method for retrieving blocks from the database. For use with
        the database the public keys need to be converted to buffer objects.
        """

        return [(entry[0], seq) for entry in self.entries for seq in entry[1]]

    def db_pack(self):
        return [(entry[0].encode('hex'), entry[1]) for entry in self.entries]
