"""
Module defining the discovery server.
"""
import logging
import json
import zmq
import signal

from zmq.eventloop.zmqstream import ZMQStream
from tornado import ioloop

from src.agent.info import AgentInfo
import src.communication.messages_pb2 as msg
from src.communication.interface import CommunicationInterface
from src.communication.messaging import MessageProcessor, MessageHandler
from src.communication.messages import NewMessage


def spawn_discovery_server(discovery):
    """
    Spawns the discovery server.
    """
    discovery.run()


class DiscoveryServer(MessageProcessor):
    """
    The discovery server keeps track of all agents. Each agent needs to register
    at this server such that they can be found by other agents.
    """

    def __init__(self):
        """
        Creates a new discovery server.
        """
        self.com = CommunicationInterface()
        self.agents = []
        self.loop = None

    def configure(self, options):
        """
        Configures the discovery server with options read from a configuration
        file.
        """
        self.port = options['discovery_port']

        self.com.configure(self.port)

    def stop_condition(self):
        """
        Check the condition and stops the main loop if condition fails.
        """
        if len(self.agents) == 0:
            self.loop.stop()

    @MessageHandler(msg.AGENT_REQUEST)
    def agent_request(self, sender, _):
        """Sends all registered agents to the sender of the request.

        Arguments:
            sender {string} -- Address of the sender of the request
            _ {msg.AgentRequest} -- An empty message
        """

        message = msg.AgentReply(agents=[agent.as_message() for agent in self.agents])
        self.com.send(sender, NewMessage(msg.AGENT_REPLY, message))

    @MessageHandler(msg.REGISTER)
    def register(self, sender, msg):
        """Registers an agent on the discovery server, bound to the REGISTER message.

        Arguments:
            sender {string} -- Address of the sender of the request
            msg {msg.Register} -- Register message body containing agent's address and public key
        """

        agent = AgentInfo.from_message(msg.agent)
        self.agents.append(agent)

        logging.info("Address: %s -> Agent: %s", agent.address, agent.public_key.as_readable())

    @MessageHandler(msg.UNREGISTER)
    def unregister(self, sender, msg):
        """Unregisters and agent from the discovery server, bound to the UNREGISTER message.

        Arguments:
            sender {string} -- Address of the sender of the request
            msg {msg.Unregister} -- Unregister message body containing AgentInfo object
        """

        agent = AgentInfo.from_message(msg.agent)
        self.agents.remove(agent)

    def on_shutdown(self):
        print('Shutting down')
        self.loop.stop()

    def run(self):
        """The main loop for the discovery server.
        """
        self.com.start(self.handle)

        self.loop = ioloop.IOLoop.current()
        cb_stop_condition = ioloop.PeriodicCallback(self.stop_condition, 1000)
        cb_stop_condition.start()
        signal.signal(signal.SIGINT,
                      lambda sig, frame: self.loop.add_callback_from_signal(self.on_shutdown))
        self.loop.start()
