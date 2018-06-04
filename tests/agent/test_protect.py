import unittest
import mock

from src.agent.protect import ProtectAgent, msg, NewMessage
from tests.helpers import generate_key, MockObject, MockBlockGenerator


class TestProtectAgent(unittest.TestCase):

    def test1(self):
        "can request a protect round"
        partner = MockObject()
        partner.address = 'world'
        a = ProtectAgent()
        a.com = mock.MagicMock()
        a.com.address = 'hello'
        a.database = MockObject()
        generator = MockBlockGenerator()
        generator.public_key = a.public_key.as_bin()
        db = []
        db.append(generator.generate_message())
        db.append(generator.generate_message())
        a.database.get_chain = lambda x: db

        a.request_protect(partner)

        a.com.send.assert_called()
        self.assertEqual(a.open_requests['world'], {})

    # def test2(self):
    #     "can request blocks in answer to a protect request"
    #     a = ProtectAgent()
    #     a.com = mock.MagicMock()
    #     a.verify_chain = lambda chain: True
    #     chain = MockObject()
    #     chain.blocks = [1, 2]

    #     a.protect_chain('world', chain)

    #     a.com.send.assert_called()
