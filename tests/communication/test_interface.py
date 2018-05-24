import unittest
import mock
import zmq
from src.communication.interface import CommunicationInterface, BASE_ADDRESS

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
        interface.start()
        
        RECV_ADDRESS = 'tcp://127.0.0.1:10001'
        ctx = zmq.Context()
        receiver = ctx.socket(zmq.PULL)
        receiver.bind(RECV_ADDRESS)
        
        MSG = {'hello': 'world'}
        interface.send(RECV_ADDRESS, MSG)
        received = receiver.recv_json()

        ctx.destroy()
        interface.stop()

        self.assertEqual(received, MSG)

    def test3(self):
        """
        two interfaces can communicate
        """
        PORT = 10000
        interface = CommunicationInterface()
        interface.configure(PORT)
        interface.start()
        
        RECV_PORT = 10001
        rec = CommunicationInterface()
        rec.configure(RECV_PORT)
        rec.start()
        
        MSG = {'hello': 'world'}
        interface.send(BASE_ADDRESS % RECV_PORT, MSG)

        received = rec.receiver.recv_json()
        self.assertEqual(received, MSG)

        rec.stop()
        interface.stop()

    