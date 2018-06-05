import random

import src.communication.messages_pb2 as msg

from src.agent.protect import ProtectAgent
from src.communication.messages import NewMessage


class BadChainProtectAgent(ProtectAgent):

    def request_protect(self, partner=None):
        while partner is None or partner == self.get_info() or \
                partner.address in self.open_requests:
            partner = random.choice(self.agents)

        if partner.address in self.open_requests:
            return
        if partner.address in self.ignore_list:
            return

        chain = self.database.get_chain(self.public_key)

        # manipulate the chain by removing an item
        chain.pop(random.randrange(len(chain)))

        db = msg.Database(info=self.get_info().as_message(),
                          blocks=[block.as_message() for block in chain])
        self.open_requests[partner.address] = {}
        self.com.send(partner.address, NewMessage(msg.PROTECT_CHAIN, db))
        self.logger.debug("[0] Requesting PROTECT with %s", partner.address)