import random
import logging

import src.communication.messages_pb2 as msg

from src.agent.simple_protect import ProtectSimpleAgent
from src.communication.messages import NewMessage
from src.agent.request_cache import RequestState


class BadChainProtectAgent(ProtectSimpleAgent):

    _type = "Incomplete chain"

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
        if len(chain) > 5:
            chain.pop(4)

        db = msg.Database(info=self.get_info().as_message(),
                          blocks=[block.as_message() for block in chain])
        self.request_cache.new(partner.address, RequestState.PROTECT_INIT)
        self.request_cache.get(partner.address).chain_length_sent = chain[-1].sequence_number
        self.com.send(partner.address, NewMessage(msg.PROTECT_CHAIN, db))

        self.logger.info("Start interaction with %s", partner.address)
