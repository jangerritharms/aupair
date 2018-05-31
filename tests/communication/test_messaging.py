import unittest
import mock
from src.communication.messaging import MessageProcessor
import src.communication.messages_pb2 as msg

class TestMessaging(unittest.TestCase):

    def test1(self):
        "Properly finds the handler and calls it"
        processor = MessageProcessor()
        mock_handler = mock.MagicMock()
        processor._message_handlers[msg.REGISTER] = mock_handler

        message = msg.WrapperMessage()
        message.type = msg.REGISTER
        message.address = "world"
        message.register.agent.public_key = "hello"
        message.register.agent.address = "world"

        processor.handle(message.register, message)
        mock_handler.assert_called_with(processor, "world", message.register)