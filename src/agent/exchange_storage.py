import src.communication.messages_pb2 as msg

from src.chain.index import BlockIndex


class ExchangeStorage(object):
    """The exchange storage keeps track of which blocks were exchanged with a certain exchange
    block. Each exchange block should be linked with an index which represents the exchange that
    happened. That link is a simple dict.
    """

    def __init__(self, entries={}):
        """Creates a new ExchangeStorage with `entries` defining the initial entries.
        """
        self.exchanges = entries

    def add_exchange(self, block, index):
        """Adds an entry for the given exchange block and index.

        Arguments:
            block {Block} -- Exchange block
            index {BlockIndex} -- Index of the exchange.
        """
        self.exchanges[block.hash] = index

    def add_exchange_storage(self, storage):
        """Adds exchanges from another storage object.

        Arguments:
            storage {ExchangeStorage} -- ExchangeStorage
        """
        for block_hash, index in storage.exchanges.iteritems():
            self.exchanges[block_hash] = index

    def as_message(self):
        """Returns an exchange message.
        """
        ex_entries = [msg.ExchangeIndexEntry(block_hash=key,
                                             index=value.as_message())
                      for key, value in self.exchanges.iteritems()]
        return msg.ExchangeIndex(entries=ex_entries)

    @classmethod
    def from_message(cls, message):
        """Creates an exchange storage from a message.
        """

        return cls({msg.block_hash: BlockIndex.from_message(msg.index) for msg in message.entries})

    def __len__(self):
        return len(self.exchanges)

    def __str__(self):
        string = "Exchange {\n\t"
        string += "\n\t".join(["%s: %s" % (block_hash.encode('hex'), index)
                               for block_hash, index in self.exchanges.iteritems()])
        string += "\n}"

        return string
