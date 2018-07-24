import random
import logging
from hashlib import sha256

import src.communication.messages_pb2 as msg

from src.agent.simple_protect import ProtectSimpleAgent
from src.communication.messages import NewMessage
from src.agent.request_cache import RequestState
from src.chain.index import BlockIndex
from src.chain.block import Block
from src.agent.request_cache import RequestCache, RequestState
from src.public_key import PublicKey


def blocks_to_hash(blocks):
    """Takes a list of blocks and creates a hash that includes the hashes of all blocks contained.

    Arguments:
        blocks {[Block]} -- List of blocks.
    """

    list_of_hashes = sorted([block.hash for block in blocks])
    hash_string = ''.join(list_of_hashes)
    if hash_string == '':
        return ''
    return sha256(hash_string).digest()


class BadChainProtectAgent(ProtectSimpleAgent):

    _type = "Incomplete chain"

    def configure_message_handlers(self):
        super(BadChainProtectAgent, self).configure_message_handlers()
        configure_badchain(self)

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


def configure_badchain(agent):

    @agent.add_handler(msg.PROTECT_BLOCKS_REPLY)
    def protect_blocks_reply(self, sender, body):
        """Handles a received PROTECT_BLOCKS_REPLY. A PROTECT exchange is ongoing, the responder
        received the blocks the initiator had more than himself. Now the responder can check that
        the blocks add up to all information of the agent as proven by the hashes of the exchange
        blocks on the chain of the initiator. If the check succeeds, the agent shows his agreement
        by sending his own chain and blocks that he has above the initiator in a
        msg.PROTECT_CHAIN_BLOCKS message. If the check fails, the agent sends a msg.PROTECT_REJECT
        message and adds the initiator to the ignore list.

        Arguments:
            sender {Address} -- Address string of the agent.
            body {msg.Database} -- Body of the incoming message.
        """

        if self.request_cache.get(sender) is None:
            logging.error('No open reqest found for this agent')
            return

        blocks = [Block.from_message(block) for block in body.blocks]

        error = self.database.add_blocks(blocks)

        if error:
            self.logger.warning("Detected double spend of agent %s", PublicKey.from_bin(error.public_key).as_readable())
        
        self.request_cache.get(sender).transfer_up = blocks_to_hash(blocks)
        self.request_cache.get(sender).transfer_up_index = BlockIndex.from_blocks(blocks)

        verification = self.verify_exchange(self.request_cache.get(sender).chain,
                                            self.request_cache.get(sender).exchanges)

        if verification:
            own_chain = self.database.get_chain(self.public_key)

            # manipulate the chain by removing an item
            if len(own_chain) > 5:
                own_chain.pop(4)

            own_index = BlockIndex.from_blocks(self.database.get_all_blocks())
            partner_index = self.request_cache.get(sender).index
            index = (own_index - partner_index)

            sub_database = []
            if len(index) == 0:
                self.request_cache.get(sender).transfer_up = ''
                self.request_cache.get(sender).transfer_up_index = BlockIndex()
            else:
                sub_database = self.database.index(index)
                self.request_cache.get(sender).transfer_down = blocks_to_hash(blocks)
                self.request_cache.get(sender).transfer_down_index = index
            self.request_cache.get(sender).chain_length_sent = len(own_chain)

            db = msg.ChainAndBlocks(chain=[block.as_message() for block in own_chain],
                                    blocks=[block.as_message() for block in sub_database],
                                    exchange=self.exchange_storage.as_message())
            self.com.send(sender, NewMessage(msg.PROTECT_CHAIN_BLOCKS, db))
            self.request_cache.get(sender).update_state(RequestState.PROTECT_EXCHANGE)

        else:
            self.logger.error("Verification of %s's exchanges failed", sender)
            self.request_cache.remove(sender)
            self.ignore_list.append(sender)
            self.com.send(sender, NewMessage(msg.PROTECT_REJECT, msg.Empty()))