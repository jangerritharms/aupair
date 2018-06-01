import unittest
import mock

from src.agent.base import BaseAgent
from src.agent.info import AgentInfo
from src.chain.block import Block
from src.communication.messages_pb2 import BLOCK_PROPOSAL
from src.communication.messages import NewMessage
from tests.helpers import generate_key


class TestBaseAgent(unittest.TestCase):

    def test1(self):
        "can start an interaction"
        A = BaseAgent()
        A.com = mock.Mock()
        A.block_factory = mock.Mock()
        block = Block()
        A.block_factory.create_new.return_value = block
        b_info = mock.Mock()
        b_info.address = "foo"
        b_info.public_key = generate_key()

        A.agents.append(b_info)
        A.request_interaction()
        A.com.send.assert_called_with("foo", NewMessage(BLOCK_PROPOSAL, block.as_message()))

    def test2(self):
        "can react to an interaction"
        A = BaseAgent()
        A.com = mock.Mock()
        A.database = mock.Mock()
        A.block_factory = mock.Mock()
        A.block_factory.create_linked.return_value = Block()
        block = Block()
        A.block_proposal("foo", block.as_message())

        A.com.send.assert_called()
