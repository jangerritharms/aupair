"""
Module defining the agent class.
"""
import os
import logging
import time
import json
import random
import zmq
from zmq.eventloop.zmqstream import ZMQStream

from tornado import ioloop

from src.pyipv8.ipv8.keyvault.crypto import ECCrypto
from src.pyipv8.ipv8.attestation.trustchain.block import TrustChainBlock, GENESIS_HASH
from src.pyipv8.ipv8.messaging.serialization import Serializer
from src.pyipv8.ipv8.attestation.trustchain.payload import HalfBlockPayload, HalfBlockPairPayload
from src.pyipv8.ipv8.attestation.trustchain.database import TrustChainDB
from src.pyipv8.ipv8.messaging.deprecated.encoding import encode
from src.messages import Message, MessageTypes
from src.database import Database
from src.utils import create_index_from_chain, create_index_from_blocks, calculate_difference

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
        self.receiver = None
        self.sender = None
        self.discovery_address = ''
        self.loop = None
        self.database = None
        self.agents = []
        self.serializer = Serializer()

        self.private_key = ECCrypto().generate_key('curve25519')
        self.public_key = self.private_key.pub()

        self.emulation_duration = 0
        self.emulation_step_length = 0
        self.address = ''

        FORMAT= '%(address)s %(message)s'
        logging.basicConfig(format=FORMAT)

        self.startup_time = 5

    def request_interaction(self, partner = None):
        """
        Requests a new interaction with the given partner.

        :param partner: Dict of the partner including public_key and address
        """
        while partner is None or partner[1]['address'] == self.address:
            partner = random.choice(self.agents)
        partner = {'public_key': partner[0], 'address': partner[1]['address']}
        new_block = TrustChainBlock.create({"up": 10, "down": 10},
                                           self.database,
                                           str(self.public_key.key_to_bin()),
                                           link_pk=str(partner['public_key']).decode('hex'))

        new_block.sign(self.private_key)
        self.database.add_block(new_block)
        self.send(partner['address'], Message(MessageTypes.BLOCK,
                                              self.address,
                                              new_block.pack().encode('base64')).to_json())
        logging.debug('%s requesting interaction with %s', self.address, partner['address'], extra={'address': self.address})

    def request_crawl(self, partner = None):
        """
        Request data from the other node.
        """
        while partner is None or partner[1]['address'] == self.address:
            partner = random.choice(self.agents)
        partner = {'public_key': partner[0], 'address': partner[1]['address']}
        self.send(partner['address'], Message(MessageTypes.CRAWL_REQUEST,
                                              self.address).to_json())

    def request_audit(self, partner = None):
        """
        Request audit request from the other node.
        """
        while partner is None or partner[1]['address'] == self.address:
            partner = random.choice(self.agents)
        partner = {'public_key': partner[0], 'address': partner[1]['address']}

        blocks = self.database._getall('WHERE public_key = ?', (buffer(self.public_key.key_to_bin()),))

        list_of_packs = []
        for block in blocks:
            list_of_packs.append(block.pack().encode('base64'))

        self.send(partner['address'], Message(MessageTypes.PA_REQUEST,
                                              self.address,
                                              list_of_packs).to_json())

    def get_agents(self):
        """
        Selects the next interaction partner.
        """
        logging.debug('Getting agents', extra={'address': self.address})
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
        self.database = TrustChainDB('', 'db_'+ str(port))
        genesis_block = TrustChainBlock()
        genesis_block.public_key = str(self.public_key.key_to_bin())
        self.database.add_block(genesis_block)

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

    def handle_message(self, message):
        """
        Handle messages received from other agents.
        """
        msg = json.loads(message[0].decode('string-escape').strip('"'))
        if msg['type'] == MessageTypes.AGENT_REPLY:
            self.agents = msg['payload']

        elif msg['type'] == MessageTypes.BLOCK:
            block = self.block_from_payload(msg['payload'])
            new_block = TrustChainBlock.create(None,
                                               self.database,
                                               str(self.public_key.key_to_bin()),
                                               link=block)
            new_block.sign(self.private_key)
            self.database.add_block(block)
            self.database.add_block(new_block)
            self.send(msg['sender'], Message(MessageTypes.BLOCK_REPLY,
                                             self.address,
                                             new_block.pack().encode('base64')).to_json())

            new_block = TrustChainBlock.create({"transfer_down": [[block.public_key, [block.sequence_number]]]},
                                               self.database,
                                               str(self.public_key.key_to_bin()),
                                               link_pk=block.public_key)
            new_block.sign(self.private_key)
            self.database.add_block(new_block)
            

        elif msg['type'] == MessageTypes.BLOCK_REPLY:
            block = self.block_from_payload(msg['payload'])

            self.database.add_block(block)
            new_block = TrustChainBlock.create({"transfer_down": [[block.public_key, [block.sequence_number]]]},
                                               self.database,
                                               str(self.public_key.key_to_bin()),
                                               link_pk=block.public_key)
            new_block.sign(self.private_key)
            self.database.add_block(new_block)

        elif msg['type'] == MessageTypes.CRAWL_REQUEST:
            blocks = self.database._getall('', ())

            list_of_packs = []
            for block in blocks:
                list_of_packs.append(block.pack().encode('base64'))

            self.send(msg['sender'], Message(MessageTypes.CRAWL_REPLY,
                                             self.address,
                                             list_of_packs).to_json())

        elif msg['type'] == MessageTypes.CRAWL_REPLY:
            list_of_packs = msg['payload']
            for pack in list_of_packs:
                block = self.block_from_payload(pack)
                if block.previous_hash != GENESIS_HASH:
                    self.database.add_block(block)

        elif msg['type'] == MessageTypes.PA_REQUEST:
            list_of_packs = msg['payload']

            chain = []
            for pack in list_of_packs:
                print pack
                block = self.block_from_payload(pack)
                chain.append(block)

            self.validate_chain(chain)

            blocks = self.calculate_difference(chain)

            list_of_packs = []
            for block in blocks:
                list_of_packs.append(block.pack().encode('base64'))

            blocks = self.database._getall('WHERE public_key = ?',
                                           (buffer(self.public_key.key_to_bin()),))

            list_of_chain = []
            for block in blocks:
                list_of_chain.append(block.pack().encode('base64'))

            self.send(msg['sender'], Message(MessageTypes.PA_REPLY,
                                             self.address,
                                             [list_of_packs, list_of_chain]).to_json())

        elif msg['type'] == MessageTypes.PA_REPLY:
            list_of_packs_and_chain = msg['payload']

            transfer = []
            for pack in list_of_packs_and_chain[0]:
                block = self.block_from_payload(pack)
                self.database.add_block(block)
                transfer.append(block)

            chain = []
            for pack in list_of_packs_and_chain[1]:
                block = self.block_from_payload(pack)
                chain.append(block)

            self.validate_chain(chain)
            blocks = self.calculate_difference(chain)
            new_block = TrustChainBlock.create({'transfer_up': create_index_from_blocks(blocks),
                                            'transfer_down': create_index_from_blocks(transfer)},
                                           self.database,
                                           self.public_key.key_to_bin(),
                                           link_pk = chain[0].public_key)
            new_block.sign(self.private_key)
            self.database.add_block(new_block)

            list_of_packs = []
            for block in blocks:
                list_of_packs.append(block.pack().encode('base64'))

            self.send(msg['sender'], Message(MessageTypes.PA_BLOCK_PROPOSAL,
                                             self.address,
                                             [new_block.pack().encode('base64'), list_of_packs]).to_json())
        elif msg['type'] == MessageTypes.PA_BLOCK_PROPOSAL:
            list_of_packs_and_block = msg['payload']

            transfer = []
            for pack in list_of_packs_and_block[1]:
                block = self.block_from_payload(pack)
                self.database.add_block(block)
                transfer.append(block)

            block = self.block_from_payload(list_of_packs_and_block[0])
            
            new_block = TrustChainBlock.create(None,
                                               self.database,
                                               str(self.public_key.key_to_bin()),
                                               link=block)
            new_block.sign(self.private_key)
            self.database.add_block(block)
            self.database.add_block(new_block)
            self.send(msg['sender'], Message(MessageTypes.PA_BLOCK_ACCEPT,
                                             self.address,
                                             new_block.pack().encode('base64')).to_json())
            new_block = TrustChainBlock.create({"transfer_down": [[block.public_key, [block.sequence_number]]]},
                                               self.database,
                                               str(self.public_key.key_to_bin()),
                                               link_pk=block.public_key)
            new_block.sign(self.private_key)
            self.database.add_block(new_block)

        elif msg['type'] == MessageTypes.PA_BLOCK_ACCEPT:
            block = self.block_from_payload(msg['payload'])

            self.database.add_block(block)
            new_block = TrustChainBlock.create({"transfer_down": [[block.public_key, [block.sequence_number]]]},
                                               self.database,
                                               str(self.public_key.key_to_bin()),
                                               link_pk=block.public_key)
            new_block.sign(self.private_key)
            self.database.add_block(new_block)



    def validate_chain(self, chain):
        """
        Checks the validity of a chain.
        """
        return True

    def calculate_difference(self, other_chain):
        """
        Calculate the set of blocks that are in this agents chain but not the partner's and return 
        them as a list.
        """
        own_chain = self.database._getall('WHERE public_key = ?',
                                          (buffer(self.public_key.key_to_bin()),))
        own_index = create_index_from_chain(own_chain, self.public_key.key_to_bin())
        other_index = create_index_from_chain(other_chain, other_chain[0].public_key)

        diff = calculate_difference(own_index, other_index)

        blocks = []
        for elem in diff:
            blocks.extend(self.database._getall('WHERE public_key = ? AND sequence_number IN (%s)' % ', '.join((str(seq) for seq in elem[1])),
                                                (buffer(elem[0]),)))
        return blocks

    def register(self):
        """
        Called by the agent to register with the discovery server.
        """
        self.send(self.discovery_address,
                  Message(MessageTypes.REGISTER,
                          self.address,
                          {'public_key': self.public_key.key_to_bin().encode('hex')}).to_json())

    def unregister(self):
        """
        Called by the agent to register with the discovery server.
        """
        self.send(self.discovery_address,
                  Message(MessageTypes.UNREGISTER,
                          self.address,
                          self.public_key.key_to_bin().encode('hex')).to_json())
        time.sleep(1)
        self.loop.stop()

    def step(self):
        """
        Emulation step in which the agent decides whether to do something or not.
        """
        choices = [True]
        # choices.extend([False]*10)
        interact = random.choice(choices)
        if interact:
            self.request_interaction()

    def send(self, address, message):
        """
        Send a message using the sending device.
        """
        self.sender.connect(address)
        self.sender.send_json(message)
        self.sender.disconnect(address)

    def write_data(self):
        """
        Writing agent data to file.
        """
        blocks = self.database._getall('', ())
        with open(os.path.join('data', self.public_key.key_to_bin().encode('hex')[20:30] + '.dat'), 'w+') as f:
            f.write('%s %s\n' % (self.public_key.key_to_bin().encode('hex'),
                               len(blocks)))
            for block in blocks:
                f.write('%s %s %d %s %d %s %s %s\n' % (
                    encode(block.transaction),
                    block.public_key.encode('hex'),
                    block.sequence_number,
                    block.link_public_key.encode('hex'),
                    block.link_sequence_number,
                    block.previous_hash.encode('hex'),
                    block.signature.encode('hex'),
                    block.hash.encode('hex')
                ))

    def run(self):
        """
        Starts the main loop of the agent.
        """
        self.context = zmq.Context()
        self.sender = self.context.socket(zmq.PUSH) # pylint: disable=no-member
        self.receiver = self.context.socket(zmq.PULL) # pylint: disable=no-member

        logging.debug('Starting agent at port %d', self.port, extra={'address': self.address})

        self.receiver.bind(self.address)
        stream = ZMQStream(self.receiver)
        stream.on_recv(self.handle_message)

        self.register()

        self.loop = ioloop.IOLoop.current()
        self.loop.call_later(self.emulation_duration*self.emulation_step_length, self.unregister)
        self.loop.call_later(self.startup_time, self.get_agents)
        cb_step = ioloop.PeriodicCallback(self.step, self.emulation_step_length*1000)
        self.loop.call_later(self.startup_time + 5, cb_step.start)
        self.loop.start()

        self.write_data()
