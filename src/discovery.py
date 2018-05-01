"""
Module defining the discovery server.
"""
import logging
import json
import zmq

from zmq.eventloop.zmqstream import ZMQStream
from tornado import ioloop

from src.messages import Message, MessageTypes

def spawn_discovery_server(discovery):
    """
    Spawns the discovery server.
    """
    discovery.run()


class DiscoveryServer(object):
    """
    The discovery server keeps track of all agents. Each agent needs to register
    at this server such that they can be found by other agents.
    """

    def __init__(self):
        """
        Creates a new discovery server.
        """
        self.context = None
        self.socket = None
        self.sender = None
        self.receiver = None
        self.port = -1
        self.agents = {}
        self.emulation_duration = 0
        self.emulation_step_length = 0
        self.loop = None

    def configure(self, options):
        """
        Configures the discovery server with options read from a configuration
        file.
        """
        self.port = options['discovery_server_port']
        self.emulation_duration = options['emulation_duration']
        self.emulation_step_length = options['emulation_step_length']

    def register_agent(self, public_key, meta):
        """
        Registers a new agent with the discovery server.
        """
        self.agents[public_key] = meta

    def unregister_agent(self, public_key):
        """
        Removes an agent from the discovery server.
        """
        del self.agents[public_key]

    def handle_message(self, stream, message):
        """
        Message handler for the incoming requests from agents.
        """
        msg = json.loads(message[0].decode('string-escape').strip('"'))
        if msg['type'] == MessageTypes.REGISTER:
            self.register_agent(msg['payload']['public_key'], {'address': msg['sender']})
        elif msg['type'] == MessageTypes.UNREGISTER:
            self.unregister_agent(msg['payload'])
        elif msg['type'] == MessageTypes.AGENT_REQUEST:
            print 'got agent message from %s', msg['sender']
            self.send(msg['sender'], Message(MessageTypes.AGENT_REPLY,
                                             None,
                                             self.agents.items()).to_json())
        else:
            logging.warning('Unhandled message of type %s', msg['type'])

    def stop_condition(self):
        """
        Check the condition and stops the main loop if condition fails.
        """
        if len(self.agents) == 0:
            self.loop.stop()

    def send(self, address, message):
        """
        Send a message using the sending device.
        """
        self.sender.connect(address)
        self.sender.send_json(message)
        self.sender.disconnect(address)

    def run(self):
        """
        The main loop for the discovery server.
        """
        context = zmq.Context()
        self.receiver = context.socket(zmq.PULL) # pylint: disable=no-member
        self.sender = context.socket(zmq.PUSH) # pylint: disable=no-member
        self.receiver.bind('tcp://*:%s' % self.port)
        stream_pull = ZMQStream(self.receiver)

        stream_pull.on_recv_stream(self.handle_message, copy=True)
        self.loop = ioloop.IOLoop.current()
        cb_stop_condition = ioloop.PeriodicCallback(self.stop_condition, 1000)
        cb_stop_condition.start()
        self.loop.start()
