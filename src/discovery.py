"""
Module defining the discovery server.
"""
import zmq
import time
import logging

from src.messages import MessageTypes

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
        self.port = -1
        self.agents = {}
        self.emulation_duration = 0
        self.emulation_step_length = 0

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
        logging.debug(self.agents)
        del self.agents[public_key]

    def handle_message(self, message):
        """
        Message handler for the incoming requests from agents.
        """
        logging.debug('Received message of type %s', message.type)
        if message.type == MessageTypes.REGISTER:
            self.register_agent(message.sender, message.payload)
        if message.type == MessageTypes.UNREGISTER:
            self.unregister_agent(message.sender)
        else:
            logging.warning('Unhandled message of type %s', message.type)

    def run(self):
        """
        The main loop for the discovery server.
        """
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PULL)
        self.socket.bind('tcp://*:%s' % self.port)

        step = 0
        while step < self.emulation_duration or len(self.agents) > 0:
            logging.debug('Discovery step')
            start = time.time()
            message = None
            try:
                message = self.socket.recv_pyobj(flags=zmq.NOBLOCK)
            except:
                pass

            if message is not None:
                self.handle_message(message)

            step += 1
            logging.debug(time.time() - start)
            if time.time() - start > self.emulation_step_length:
                logging.debug('waiting %s', self.emulation_step_length - (time.time() - start))
                time.sleep(self.emulation_step_length - (time.time() - start))
