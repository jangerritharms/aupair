import src.communication.messages_pb2 as msg


from src.agent.simple_protect import ProtectSimpleAgent, blocks_to_hash
from src.agent.base import configure_base
from src.chain.block import Block
from src.communication.messages import NewMessage
from src.chain.index import BlockIndex


class NoVerificationAgent(ProtectSimpleAgent):

    _type = "Verification free-rider"

    def configure_message_handlers(self):
        super(NoVerificationAgent, self).configure_message_handlers()
        configure_noverification(self)

    def verify_exchange(self, chain, exchange):
        return True

    def verify_chain(self, chain, expected_lenth):
        return True

    def found_double_spend(self, own_version, blocks):
        pass

def configure_noverification(agent):

    @agent.add_handler(msg.BLOCK_AGREEMENT)
    def block_confirm(self, sender, body):
        block = Block.from_message(body)
        index = BlockIndex.from_blocks([block])
        payload = {'transfer_down': blocks_to_hash([block]).encode('hex')}
        exchange_block = self.block_factory.create_new(self.get_info().public_key, payload)
        self.exchange_storage.add_exchange(exchange_block, index)

        self.database.add(block)
        self.logger.debug("Block database: %s",
                          BlockIndex.from_blocks(self.database.get_all_blocks()))

        self.logger.info("Exchange and transaction with %s completed", sender)

        self.request_cache.remove(sender)

    @agent.add_handler(msg.BLOCK_PROPOSAL)
    def block_proposal(self, sender, body):
        block = Block.from_message(body)
        index = BlockIndex.from_blocks([block])
        payload = {'transfer_down': blocks_to_hash([block]).encode('hex')}
        exchange_block = self.block_factory.create_new(self.get_info().public_key, payload)
        self.exchange_storage.add_exchange(exchange_block, index)

        self.database.add(block)

        new_block = self.block_factory.create_linked(block)
        self.com.send(sender, NewMessage(msg.BLOCK_AGREEMENT, new_block.as_message()))

        self.logger.debug("Block database: %s",
                          BlockIndex.from_blocks(self.database.get_all_blocks()))

        self.request_cache.remove(sender)