"""
Module defining the agent class.
"""
import logging
import time
import json
import random
import zmq
from zmq.eventloop.zmqstream import ZMQStream

from tornado import ioloop

from src.pyipv8.ipv8.keyvault.crypto import ECCrypto
from src.pyipv8.ipv8.attestation.trustchain.block import TrustChainBlock
from src.pyipv8.ipv8.messaging.serialization import Serializer
from src.pyipv8.ipv8.attestation.trustchain.payload import HalfBlockPayload, HalfBlockPairPayload
from src.messages import Message, MessageTypes
from src.database import Database

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
        self.discovery_client = None
        self.receiver = None
        self.discovery_address = ''
        self.loop = None
        self.database = Database()
        self.serializer = Serializer()

        self.private_key = ECCrypto().generate_key('curve25519')
        self.public_key = self.private_key.pub()

        self.emulation_duration = 0
        self.emulation_step_length = 0
        self.address = ''
        
        random.seed(1010)

        self.database.add(TrustChainBlock())

    def request_interaction(self, partner):
        """
        Requests a new interaction with the given partner.

        :param partner: Dict of the partner including public_key and address
        """
        new_block = TrustChainBlock.create({"up": 10, "down": 10},
                                           self.database,
                                           str(self.public_key.key_to_bin()),
                                           link_pk=str(partner['public_key']))
        new_block.sign(self.private_key)
        self.send(partner['address'], Message(MessageTypes.BLOCK,
                                              self.address,
                                              new_block.pack().encode('base64')).to_json())

    def request_audit(self):
        pass


    def select_next_interaction_partner(self):
        """
        Selects the next interaction partner.
        """
        self.send(self.discovery_address, Message(MessageTypes.AGENT_REQUEST,
                                                  self.address).to_json())

    def configure(self, options, port):
        """
        Configures the behavior of the agent.

        :param options: Dict with configuration options
        :param port: Socket port for this agent to run on
        """
        self.emulation_duration = options['emulation_duration']
        self.emulation_step_length = options['emulation_step_length']
        self.port = port
        self.discovery_address = 'tcp://localhost:' + str(options['discovery_server_port'])

        self.address = 'tcp://127.0.0.1:'+ str(self.port)

    def block_from_payload(self, payload):
        """
        Constructs a block from a message payload string.
        """
        unpacked_list = self.serializer.unpack_multiple_as_list(HalfBlockPayload.format_list,
                                                                payload.decode('base64'))
        payload = HalfBlockPayload.from_unpack_list(*unpacked_list[0][0])
        return TrustChainBlock.from_payload(payload, self.serializer)

    def block_pair_from_payload(self, payload):
        """
        Constructs a pair of blocks from a message payload string.
        """
        unpacked_list = self.serializer.unpack_multiple_as_list(HalfBlockPairPayload.format_list,
                                                                payload.decode('base64'))
        payload = HalfBlockPairPayload.from_unpack_list(*unpacked_list[0][0])
        return TrustChainBlock.from_pair_payload(payload, self.serializer)


    def handle_message(self, stream, message):
        """
        Handle messages received from other agents.
        """
        msg = json.loads(message[0].decode('string-escape').strip('"'))
        if msg['type'] == MessageTypes.AGENT_REPLY:
            partner = random.choice(msg['payload'])
            self.request_interaction({'public_key': partner[0], 'address': partner[1]['address']})
        elif msg['type'] == MessageTypes.BLOCK:
            block = self.block_from_payload(msg['payload'])
            new_block = TrustChainBlock.create(None,
                                               self.database,
                                               str(self.public_key.key_to_bin()),
                                               link=block)
            new_block.sign(self.private_key)
            self.send(msg['sender'], Message(MessageTypes.BLOCK_REPLY,
                                             self.address,
                                             new_block.pack().encode('base64')).to_json())
        elif msg['type'] == MessageTypes.BLOCK_REPLY:
            block = self.block_from_payload(msg['payload'])
            self.database.add(block)
            new_block = TrustChainBlock.create(None,
                                               self.database,
                                               str(self.public_key.key_to_bin()),
                                               link=block)
            new_block.sign(self.private_key)
            self.database.add(block)
            payload = HalfBlockPairPayload.from_half_blocks(block, new_block).to_pack_list()
            packet = self.serializer.pack_multiple(payload)
            self.send(msg['sender'], Message(MessageTypes.BLOCK_PAIR,
                                             self.address,
                                             packet.encode('base64')).to_json())
        elif msg['type'] == MessageTypes.BLOCK_PAIR:
            block1, block2 = self.block_pair_from_payload(msg['payload'])
            self.database.add(block1)
            self.database.add(block2)

    def register(self):
        """
        Called by the agent to register with the discovery server.
        """
        self.send(self.discovery_address, Message(MessageTypes.REGISTER,
                                         self.address,
                                         {'public_key': self.public_key.key_to_bin().encode('hex')}).to_json())

    def unregister(self):
        """
        Called by the agent to register with the discovery server.
        """
        self.send(self.discovery_address, Message(MessageTypes.UNREGISTER,
                                                  self.address,
                                                  self.public_key.key_to_bin().encode('hex')).to_json())
        time.sleep(1)
        self.loop.stop()

    def step(self):
        """
        Emulation step in which the agent decides whether to do something or not.
        """
        choices = [True]
        choices.extend([False]*1000)
        interact = random.choice(choices)
        if interact:
            self.select_next_interaction_partner()

    def send(self, address, message):
        """
        Send a message using the sending device.
        """
        self.sender.connect(address)
        self.sender.send_json(message)
        self.sender.disconnect(address)

    def run(self):
        """
        Starts the main loop of the agent.
        """
        self.context = zmq.Context()
        self.sender = self.context.socket(zmq.PUSH) # pylint: disable=no-member
        self.receiver = self.context.socket(zmq.PULL) # pylint: disable=no-member

        logging.debug('Starting agent at port %d', self.port)
        self.receiver.bind(self.address)
        stream = ZMQStream(self.receiver)
        stream.on_recv_stream(self.handle_message)

        self.register()

        self.loop = ioloop.IOLoop.current()
        self.loop.call_later(self.emulation_duration*self.emulation_step_length, self.unregister)
        cb_step = ioloop.PeriodicCallback(self.step, self.emulation_step_length*1000)
        self.loop.call_later(1, lambda: cb_step.start())
        self.loop.start()
