import unittest
import src.communication.messages_pb2 as msg
from src.communication.messages import NewMessage


class TestMessages(unittest.TestCase):

    def test1(self):
        "Creates a proper message"
        register_msg = msg.Register()
        register_msg.agent.public_key = "hello"
        register_msg.agent.address = "world"
        message = NewMessage(msg.REGISTER, register_msg)

        self.assertEqual(type(message.message), msg.WrapperMessage)