"""
Module defining the agent class.
"""
import logging
import time
import zmq

from tornado import ioloop

from src.pyipv8.ipv8.keyvault.crypto import ECCrypto
from src.messages import Message, MessageTypes

def spawn_agent(agent):
    """
    Spawns the agents for the experiment.
    """
    agent.run()

class Agent(object):
    """
    Agents are the entities in the network that perform interactions. An agent
    is identified by its public key.
    """

    def __init__(self):
        """
        Creates a new agent.
        """
        self.context = None
        self.port = -1
        self.discovery = None
        self.receiver = None
        self.discovery_address = ''
        self.loop = None

        self.private_key = ECCrypto().generate_key('curve25519')
        self.public_key = self.private_key.pub()

        self.emulation_duration = 0
        self.emulation_step_length = 0
        self.address = ''

    def request_interaction(self):
        pass


    def request_audit(self):
        pass


    def select_next_interaction_partner(self):
        pass

    def configure(self, options, port):
        """
        Configures the behavior of the agent.
        """
        self.emulation_duration = options['emulation_duration']
        self.emulation_step_length = options['emulation_step_length']
        self.port = port
        self.discovery_address = 'tcp://localhost:' + str(options['discovery_server_port'])

        self.address = 'tcp://*:'+ str(self.port)

    def handle_message(self, message):
        """
        Handle messages received from other agents.
        """
        pass

    def register(self):
        """
        Called by the agent to register with the discovery server.
        """
        self.discovery.send_json(Message(MessageTypes.REGISTER,
                                         self.public_key.key_to_bin(),
                                         {'address': self.address}).to_json())

    def unregister(self):
        """
        Called by the agent to register with the discovery server.
        """
        self.discovery.send_json(Message(MessageTypes.UNREGISTER,
                                         self.public_key.key_to_bin()).to_json())
        time.sleep(1)
        self.loop.stop()


    def run(self):
        """
        Starts the main loop of the agent.
        """
        self.context = zmq.Context()
        self.receiver = self.context.socket(zmq.PULL) # pylint: disable=no-member
        self.discovery = self.context.socket(zmq.PUSH) # pylint: disable=no-member
        logging.debug('Starting agent at port %d', self.port)
        self.receiver.bind(self.address)
        self.discovery.connect(self.discovery_address)

        self.register()

        self.loop = ioloop.IOLoop.current()
        self.loop.call_later(10, self.unregister)
        self.loop.start()
