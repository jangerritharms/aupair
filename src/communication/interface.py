"""
Module defining the communication interface class.

author: Jan-Gerrit Harms
email: j.harms@student.tudelft.nl
"""
import json
import zmq
from zmq.eventloop.zmqstream import ZMQStream

from src.communication.messages_pb2 import WrapperMessage

BASE_ADDRESS = "tcp://127.0.0.1:%d"

class CommunicationInterface:
    """
    This class handles the communication between agents. It offers functions 
    for sending messages to other agents and registering message handlers.
    """

    def __init__(self):
        """
        Creates a new CommunicationInterface and defines class attributes.
        """

        self.port = -1
        self.receiver = None
        self.sender = None
        self.address = None
        self.handler = None

    def send(self, address, message):
        """
        Sends a message to another agent.
        
        Arguments:
            address {string} -- Address of the receiving agent.
            message {Message} -- Message to send to the receiving agent.
        """

        assert self.sender is not None, "Sending device is not initialized yet"

        message.set_sender(self.address)

        self.sender.connect(address)

        if hasattr(message, 'to_json'):
            self.sender.send_json(message.to_json())
        else:
            self.sender.send(message.message.SerializeToString())
        
        self.sender.disconnect(address)

    def configure(self, port):
        """
        Configures the CommunicationInterface instance.
        
        Arguments:
            port {int} -- Port on which this instance will listen to incoming 
                          messages.
        """

        self.port = port
        self.address = BASE_ADDRESS % self.port

    def handle_message(self, messages):
        """
        Forwards a received message to the registered message handler.

        Arguments:
            messages {[Message]} -- List of messages received from the receiver 
                                    device
        """
        msg = None
        wrapped_msg = None
        try:
            msg = json.loads(messages[0].decode('string-escape').strip('"'))
        except:
            wrapped_msg = WrapperMessage()
            wrapped_msg.ParseFromString(messages[0])
            msg = getattr(wrapped_msg, wrapped_msg.WhichOneof('msg'))
        self.handler(msg, wrapped_msg)

    def start(self, handler):
        """
        Starts listening on the receiving port and opens the sending device. This
        needs to be executed from the same process as the one that sends the actual
        messages, because the zmq Context is bound to a process.
        """

        self.context = zmq.Context()
        self.sender = self.context.socket(zmq.PUSH)
        self.receiver = self.context.socket(zmq.PULL)

        self.receiver.bind(self.address)
        stream = ZMQStream(self.receiver)
        stream.on_recv(self.handle_message)

        self.handler = handler

    def stop(self):
        """
        Properly close the sockets and unbind the addresses.
        """
        self.context.destroy()