import random
import logging

import src.communication.messages_pb2 as msg

from src.agent.simple_protect import ProtectSimpleAgent
from src.communication.messages import NewMessage
from src.agent.request_cache import RequestState


class DoubleSpendAgent(ProtectSimpleAgent):

    _type = "Double spender"

    def __init__(self, *args, **kwargs):
        super(DoubleSpendAgent, self).__init__(*args, **kwargs)
        self.has_doublespent = False

    def verify_exchange(self, chain, exchanges):
        return True

    def request_protect(self, partner=None):
        while partner is None or partner == self.get_info():
            partner = random.choice(self.agents)

        if self.request_cache.get(partner.address) is not None:
            self.logger.warning('Request already open, ignoring request with %s', partner.address)
            return
        if partner.address in self.ignore_list:
            return

        chain = self.database.get_chain(self.public_key)

        # manipulate the chain by removing an item
        if len(chain) > 3 and not self.has_doublespent:
            if chain[-1].is_transaction():
                self.logger.error("DOULBE SPENDING BABYYYYYYYYYYYYYYYYYYYYYYYYYYYYY")
                block = chain[-1]
                self.logger.error("Block removed: %s", block)
                self.database.delete(self.public_key, block.sequence_number, 1)
                self.has_doublespent = True

        chain = self.database.get_chain(self.public_key)

        db = msg.Database(info=self.get_info().as_message(),
                          blocks=[block.as_message() for block in chain])
        self.request_cache.new(partner.address, RequestState.PROTECT_INIT)
        self.request_cache.get(partner.address).chain_length_sent = len(chain)
        self.com.send(partner.address, NewMessage(msg.PROTECT_CHAIN, db))

        self.logger.info("Start interaction with %s", partner.address)