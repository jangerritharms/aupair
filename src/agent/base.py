import os
import random
import time
import pickle

from tornado import ioloop

import src.communication.messages_pb2 as msg

from src.pyipv8.ipv8.keyvault.crypto import ECCrypto
from src.pyipv8.ipv8.attestation.trustchain.payload import HalfBlockPayload, HalfBlockPairPayload
from src.pyipv8.ipv8.messaging.serialization import Serializer
from src.pyipv8.ipv8.attestation.trustchain.block import TrustChainBlock
from src.public_key import PublicKey
from src.database import Database
from src.block_factory import BlockFactory
from src.agent.info import AgentInfo
from src.communication.interface import CommunicationInterface
from src.communication.messages import Message, MessageTypes, NewMessage
from src.communication.messaging import MessageProcessor, MessageHandler


class BaseAgent(MessageProcessor):
    """The BaseAgent class defines the default honest behavior for agents and includes all the
    attributes and functions to properly interact with the network, including the public and private
    keys, the communication interface and block creation tools. Also some default message handlers
    for replying to blocks, registering and unregistering are included.
    """

    def __init__(self):
        """Creates a new BaseAgent, creates keys and declares class attributes.
        """
        self.agents = []

        self.options = {}

        self.private_key = ECCrypto().generate_key('curve25519')
        self.public_key = PublicKey(self.private_key.pub())

        self.com = CommunicationInterface()
        self.database = None
        self.block_factory = None
        self.serializer = Serializer()


    def setup(self, options, port):
        """Loads a configuration for the agent. The configuration includes the discovery server
        address and experiment settings like the duration of the experiment. Also initializes
        components which depend on the configuration of this particular agent.

        Arguments:
            options {ExperimentOptions} -- Options for the Experiment
            port {unsinged int} -- Port for the receiver of the agent
        """

        self.options['duration'] = options['emulation_duration']
        self.options['startup_time'] = options['startup_time']
        self.options['discovery_server'] = 'tcp://localhost:' + str(options['discovery_port'])

        self.database = Database('', 'db_' + str(port))
        self.block_factory = BlockFactory(self.database, self.public_key, self.private_key)
        self.block_factory.create_genesis()

        self.com.configure(port)

    def get_info(self):
        """Return information about the agent.

        Returns:
            AgentInfo -- Info object about the agent.
        """

        return AgentInfo.from_agent(self)

    def request_interaction(self, partner=None):
        """Sends a block proposal to another known agent.

        Keyword Arguments:
            partner {AgentInfo} -- Contact information about the partner for the new interaction. If
            this is None, a partner will be selected according to the
            interaction_partner_selection_strategy. (default: {None})
        """

        while partner is None or partner == self.get_info():
            partner = random.choice(self.agents)
        self.last_interaction_partner = partner

        new_block = self.block_factory.create_new(partner.public_key)
        self.com.send(partner.address, Message(MessageTypes.BLOCK,
                                               new_block.pack().encode('base64')))

    def request_agents(self):
        """Send a request for agents to the discovery server.
        """

        self.com.send(self.options['discovery_server'],
                      NewMessage(msg.AGENT_REQUEST, msg.Empty()))

    def block_from_payload(self, payload):
        """Constructs a block from a message payload string.
        """

        unpacked_list = self.serializer.unpack_multiple_as_list(HalfBlockPayload.format_list,
                                                                payload.decode('base64'))
        payload = HalfBlockPayload.from_unpack_list(*unpacked_list[0][0])
        return TrustChainBlock.from_payload(payload, self.serializer)

    def block_pair_from_payload(self, payload):
        """Constructs a pair of blocks from a message payload string.
        """

        unpacked_list = self.serializer.unpack_multiple_as_list(HalfBlockPairPayload.format_list,
                                                                payload.decode('base64'))
        payload = HalfBlockPairPayload.from_unpack_list(*unpacked_list[0][0])
        return TrustChainBlock.from_pair_payload(payload, self.serializer)

    @MessageHandler(msg.AGENT_REPLY)
    def set_agents(self, sender, body):
        self.agents = [AgentInfo.from_message(agent) for agent in body.agents]

    @MessageHandler(MessageTypes.BLOCK)
    def block_proposal(self, sender, payload):
        block = self.block_from_payload(payload)
        self.database.add(block)

        new_block = self.block_factory.create_linked(block)
        self.com.send(sender, Message(MessageTypes.BLOCK_REPLY, new_block.pack().encode('base64')))

    @MessageHandler(MessageTypes.BLOCK_REPLY)
    def block_confirm(self, sender, payload):
        block = self.block_from_payload(payload)

        self.database.add(block)

    def register(self):
        """Sends a registration message to the discovery server with the agent's contact info. This
        announces to the network that the agent is available for interactions.
        """

        message = msg.Register(agent=self.get_info().as_message())
        self.com.send(self.options['discovery_server'], NewMessage(msg.REGISTER, message))

    def unregister(self):
        """Sends a unregistration message to the discovery server with the agent's contact info.
        This announces to the network that the agent is about to leave the network.
        """

        message = msg.Unregister(agent=self.get_info().as_message())
        self.com.send(self.options['discovery_server'], NewMessage(msg.UNREGISTER, message))
        time.sleep(1)
        self.loop.stop()

    def step(self):
        """Defines the behavior of the agent. This function is called every 0.01 seconds. Each call
        the agent decides according to some strategy whether to perform an action or not.
        """

        choices = [True, False, False, False, False]
        interact = random.choice(choices)

        self.request_interaction()

    def write_data(self):
        """Serializes the state of the agent in order to be analyzed afterwards.
        """

        blocks = self.database._getall('', ())
        with open(os.path.join('data', self.public_key.as_readable() + '.dat'), 'w+') as f:
            f.write('%s %s\n' % (self.public_key.as_hex(), len(blocks)))
            for block in blocks:
                f.write('%s %s %d %s %d %s %s %s\n' % (
                    pickle.dumps(block.transaction).encode('hex'),
                    block.public_key.encode('hex'),
                    block.sequence_number,
                    block.link_public_key.encode('hex'),
                    block.link_sequence_number,
                    block.previous_hash.encode('hex'),
                    block.signature.encode('hex'),
                    block.hash.encode('hex')
                ))

    def run(self, dishonest=False):
        """
        Starts the main loop of the agent.
        """
        self.com.start(self.handle)

        self.register()

        self.loop = ioloop.IOLoop.current()
        self.loop.call_later(self.options['duration'], self.unregister)
        self.loop.call_later(self.options['startup_time'], self.request_agents)
        cb_step = ioloop.PeriodicCallback(self.step, 1000)
        self.loop.call_later(self.options['startup_time'] + 5, cb_step.start)
        self.loop.start()

        self.write_data()
