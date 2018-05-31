import unittest
import mock
import zmq
from src.communication.interface import CommunicationInterface, BASE_ADDRESS
from src.communication.messages import NewMessage
import src.communication.messages_pb2 as msg


TEST_MSG = NewMessage(msg.REGISTER, msg.Register(agent=msg.AgentInfo(
    public_key="hello", address="world"
)))

class TestCommunicationInterface(unittest.TestCase):
    def test1(self):
        """
        configure sets the right port and address
        """
        PORT = 10000
        interface = CommunicationInterface()
        interface.configure(PORT)
        
        self.assertEqual(interface.port, PORT)
        self.assertEqual(interface.address, 'tcp://127.0.0.1:%d' % PORT)


    def test2(self):
        """
        sends a message to another agent.
        """
        PORT = 10000
        interface = CommunicationInterface()
        interface.configure(PORT)
        interface.start(lambda: None)
        
        RECV_ADDRESS = 'tcp://127.0.0.1:10001'
        ctx = zmq.Context()
        receiver = ctx.socket(zmq.PULL)
        receiver.bind(RECV_ADDRESS)
        
        interface.send(RECV_ADDRESS, TEST_MSG)
        received = receiver.recv()

        ctx.destroy()
        interface.stop()

        received_message = msg.WrapperMessage()
        received_message.ParseFromString(received)
        self.assertEqual(received_message.type, msg.REGISTER)

    

    