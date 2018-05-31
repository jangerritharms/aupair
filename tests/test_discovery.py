import unittest

import src.communication.messages_pb2 as msg
from src.communication.messages import NewMessage
from src.discovery import DiscoveryServer

from tests.helpers import TEST_PK

class TestDiscoveryServer(unittest.TestCase):

    def test1(self):
        "Can register an agent"

        d = DiscoveryServer()
        register_msg = msg.Register(agent=msg.AgentInfo(
            public_key=TEST_PK.as_hex(), address="world"
        ))
        d.register("world", register_msg)

        self.assertEqual(len(d.agents), 1)
        self.assertEqual(d.agents[0].public_key.as_hex(), TEST_PK.as_hex())
        self.assertEqual(d.agents[0].address, "world")

    def test2(self):
        "Can unregister an agent"

        d = DiscoveryServer()
        register_msg = msg.Register(agent=msg.AgentInfo(
            public_key=TEST_PK.as_hex(), address="world"
        ))
        unregister_msg = msg.Unregister(agent=msg.AgentInfo(
            public_key=TEST_PK.as_hex(), address="world"
        ))
        d.register("world", register_msg)
        d.unregister("world", unregister_msg)

        self.assertEqual(len(d.agents), 0)