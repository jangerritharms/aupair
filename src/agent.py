"""
Module defining the agent class.
"""
import os
import logging
import time
import json
import random
import pickle
import zmq
from sqlite3 import IntegrityError
from zmq.eventloop.zmqstream import ZMQStream

from tornado import ioloop

from src.pyipv8.ipv8.keyvault.crypto import ECCrypto
from src.pyipv8.ipv8.attestation.trustchain.block import TrustChainBlock, GENESIS_HASH, UNKNOWN_SEQ
from src.pyipv8.ipv8.messaging.serialization import Serializer
from src.pyipv8.ipv8.attestation.trustchain.payload import HalfBlockPayload, HalfBlockPairPayload
from src.pyipv8.ipv8.attestation.trustchain.database import TrustChainDB
from src.pyipv8.ipv8.messaging.deprecated.encoding import encode
from src.pyipv8.ipv8.database import sqlite3
from src.communication.messages import Message, MessageTypes
from src.database import Database
from src.utils import create_index_from_chain, create_index_from_blocks, calculate_difference
from src.communication.messaging import MessageProcessor, MessageHandler
from src.communication.interface import CommunicationInterface


class Agent(MessageProcessor):
    """
    Agents are the entities in the network that perform interactions. An agent
    is identified by its public key.
    """

    def __init__(self):
        """
        Creates a new agent.
        """
        self.dishonest = False
        self.crawling = False
        self.syncing = False
        self.last_interaction_partner = None
        self.start_time = None

        self.context = None
        self.port = -1
        self.receiver = None
        self.sender = None
        self.discovery_address = ''
        self.loop = None
        self.database = None
        self.agents = []
        self.com = CommunicationInterface()
        self.serializer = Serializer()

        self.private_key = ECCrypto().generate_key('curve25519')
        self.public_key = self.private_key.pub()

        self.emulation_duration = 0
        self.emulation_step_length = 0
        self.address = ''

        FORMAT= '%(address)s %(message)s'
        logging.basicConfig(format=FORMAT)

        self.startup_time = 5

    def configure(self, options, port):
        """
        Configures the behavior of the agent.

        :param options: Dict with configuration options
        :param port: Socket port for this agent to run on
        """
        self.emulation_duration = options['emulation_duration']
        self.emulation_step_length = options['emulation_step_length']
        self.discovery_address = 'tcp://localhost:' + str(options['discovery_server_port'])
        self.database = TrustChainDB('', 'db_'+ str(port))
        genesis_block = TrustChainBlock()
        genesis_block.public_key = str(self.public_key.key_to_bin())
        self.database.add_block(genesis_block)

        self.com.configure(port)

        self.crawling = options['enable_crawling']
        self.syncing = options['enable_syncing']
        if self.syncing:
            print self.syncing


    def request_interaction(self, partner=None, double_spend=False):
        """
        Requests a new interaction with the given partner.

        :param partner: Dict of the partner including public_key and address
        """
        while partner is None or partner[1]['address'] == self.address:
            partner = random.choice(self.agents)
        self.last_interaction_partner = partner
        partner = {'public_key': partner[0], 'address': partner[1]['address']}

        if double_spend:
            logging.debug('%s double spending', self.address)
            latest = self.database.get_latest(self.public_key.key_to_bin())
            if latest.link_sequence_number == UNKNOWN_SEQ and latest.transaction.get('transfer_down'):
                self.database.execute(
                        'DELETE FROM blocks WHERE public_key = ? AND sequence_number IN (?,?)',
                        (buffer(self.public_key.key_to_bin()),
                        latest.sequence_number -1,
                        latest.sequence_number))
            else:
                self.database.execute(
                        'DELETE FROM blocks WHERE public_key = ? AND sequence_number = ?',
                        (buffer(self.public_key.key_to_bin()), latest.sequence_number))

        new_block = TrustChainBlock.create({"up": 10, "down": 10},
                                           self.database,
                                           str(self.public_key.key_to_bin()),
                                           link_pk=str(partner['public_key']).decode('hex'))

        new_block.sign(self.private_key)
        logging.debug('%s adding block %s', self.address, new_block)
        self.database.add_block(new_block)
        self.send(partner['address'], Message(MessageTypes.BLOCK,
                                              new_block.pack().encode('base64')))
        logging.debug('%s requesting interaction with %s', self.address, partner['address'], extra={'address': self.address})

    def request_crawl(self, partner=None):
        """
        Request data from the other node.
        """
        while partner is None or partner[1]['address'] == self.address:
            partner = random.choice(self.agents)
        partner = {'public_key': partner[0], 'address': partner[1]['address']}
        self.send(partner['address'], Message(MessageTypes.CRAWL_REQUEST))

    def request_audit(self, partner=None):
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

        logging.debug('%s requesting audit from %s', self.address, partner['address'])
        self.send(partner['address'], Message(MessageTypes.PA_REQUEST,
                                              list_of_packs))

    def get_agents(self):
        """
        Selects the next interaction partner.
        """
        logging.debug('Getting agents', extra={'address': self.address})
        self.send(self.discovery_address, Message(MessageTypes.AGENT_REQUEST))

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

    @MessageHandler(MessageTypes.AGENT_REPLY)
    def set_agents(self, sender, agents):
        self.agents = agents

    @MessageHandler(MessageTypes.BLOCK)
    def block_proposal(self, sender, payload):
        block = self.block_from_payload(payload)
        new_block = TrustChainBlock.create(None,
                                            self.database,
                                            str(self.public_key.key_to_bin()),
                                            link=block)
        new_block.sign(self.private_key)

        try:
            self.database.add_block(block)
        except sqlite3.IntegrityError:
            logging.warning('%s Error adding block %s', self.address, block)
        self.database.add_block(new_block)
        self.send(sender, Message(MessageTypes.BLOCK_REPLY,
                                            new_block.pack().encode('base64')))

    @MessageHandler(MessageTypes.BLOCK_REPLY)
    def block_confirm(self, sender, payload):
        block = self.block_from_payload(payload)

        try:
            self.database.add_block(block)
            logging.debug('%s adding block %s', self.address, block)
        except sqlite3.IntegrityError:
            logging.warning('%s Error adding block %s', self.address, block)

    @MessageHandler(MessageTypes.CRAWL_REQUEST)
    def crawl_request_handler(self, sender, payload):
        blocks = self.database._getall('WHERE public_key = ?',
                                        (buffer(self.public_key.key_to_bin()),))

        list_of_packs = []
        for block in blocks:
            list_of_packs.append(block.pack().encode('base64'))

        self.send(sender, Message(MessageTypes.CRAWL_REPLY,
                                            list_of_packs))

    @MessageHandler(MessageTypes.CRAWL_REPLY)
    def crawl_reply_handler(self, sender, payload):
        list_of_packs = payload
        for pack in list_of_packs:
            block = self.block_from_payload(pack)
            if block.previous_hash != GENESIS_HASH:
                # Some of the crawled blocks may already be in the database.
                try:
                    logging.debug('%s adding block %s', self.address, block)
                    self.database.add_block(block)
                except:
                    pass

    @MessageHandler(MessageTypes.PA_REQUEST)
    def audit_request_handler(self, sender, payload):
        logging.debug('%s received audit request from %s', self.address, sender)
        list_of_packs = payload

        chain = []
        for pack in list_of_packs:
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

        self.send(sender, Message(MessageTypes.PA_REPLY,
                                         [list_of_packs, list_of_chain]))

    @MessageHandler(MessageTypes.PA_REPLY)
    def audit_reply_handler(self, sender, payload):
        logging.debug('%s received audit reply from %s', self.address, sender)
        list_of_packs_and_chain = payload

        transfer = []
        for pack in list_of_packs_and_chain[0]:
            block = self.block_from_payload(pack)
            try:
                logging.debug('%s adding block %s', self.address, block)
                self.database.add_block(block)
            except sqlite3.IntegrityError:
                logging.warning('%s Error adding block %s', self.address, block)
                existing = self.database.get(block.public_key, block.sequence_number)
                if existing.hash != block.hash:
                    logging.warning('DOUBLE SPENDING DETECTED after %d seconds', self.start_time - time.time())
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
                                            link_pk=chain[0].public_key)
        new_block.sign(self.private_key)
        logging.debug('%s adding block %s', self.address, new_block)
        self.database.add_block(new_block)

        list_of_packs = []
        for block in blocks:
            list_of_packs.append(block.pack().encode('base64'))

        self.send(sender, Message(MessageTypes.PA_BLOCK_PROPOSAL,
                                         [new_block.pack().encode('base64'),list_of_packs]))

    @MessageHandler(MessageTypes.PA_BLOCK_PROPOSAL)
    def audit_block_handler(self, sender, payload):
        list_of_packs_and_block = payload

        transfer = []
        for pack in list_of_packs_and_block[1]:
            block = self.block_from_payload(pack)
            try:
                self.database.add_block(block)
            except sqlite3.IntegrityError:
                logging.warning('%s Error adding block %s', self.address, block)
                existing = self.database.get(block.public_key, block.sequence_number)
                if existing.hash != block.hash:
                    logging.warning('DOUBLE SPENDING DETECTED after %d seconds', self.start_time - time.time())
            transfer.append(block)

        block = self.block_from_payload(list_of_packs_and_block[0])
        self.database.add_block(block)
        
        new_block = TrustChainBlock.create(None,
                                            self.database,
                                            str(self.public_key.key_to_bin()),
                                            link=block)
        new_block.sign(self.private_key)
        logging.debug('%s adding block %s', self.address, block)
        self.database.add_block(new_block)
        self.send(sender, Message(MessageTypes.PA_BLOCK_ACCEPT,
                                         new_block.pack().encode('base64')))
        new_block = TrustChainBlock.create({"transfer_down": [[block.public_key, [block.sequence_number]]]},
                                            self.database,
                                            str(self.public_key.key_to_bin()),
                                            link_pk=block.public_key)
        new_block.sign(self.private_key)
        logging.debug('%s adding block %s', self.address, new_block)
        self.database.add_block(new_block)

    @MessageHandler(MessageTypes.PA_BLOCK_ACCEPT)
    def audit_confirm_handler(self, sender, payload):
        block = self.block_from_payload(payload)

        logging.debug('%s adding block %s', self.address, block)
        self.database.add_block(block)
        new_block = TrustChainBlock.create({"transfer_down": [[block.public_key, [block.sequence_number]]]},
                                            self.database,
                                            str(self.public_key.key_to_bin()),
                                            link_pk=block.public_key)
        new_block.sign(self.private_key)
        logging.debug('%s adding block %s', self.address, new_block)
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
                          {'public_key': self.public_key.key_to_bin().encode('hex')}))

    def unregister(self):
        """
        Called by the agent to register with the discovery server.
        """
        self.send(self.discovery_address,
                  Message(MessageTypes.UNREGISTER,
                          self.public_key.key_to_bin().encode('hex')))
        time.sleep(1)
        self.loop.stop()

    def step(self):
        """
        Emulation step in which the agent decides whether to do something or not.
        """
        if self.start_time is None:
            self.start_time = time.time()
        choices = [True, False, False, False, False]
        interact = random.choice(choices)

        if self.dishonest and random.choice(choices):
            self.request_interaction(double_spend=True)
        self.request_interaction()

        if self.crawling:
            self.request_crawl()

    def send(self, address, message):
        """
        Send a message using the sending device.
        """
        self.com.send(address, message)

    def write_data(self):
        """
        Writing agent data to file.
        """
        blocks = self.database._getall('', ())
        chain = self.database._getall('WHERE public_key = ?',
                                      (buffer(self.public_key.key_to_bin()),))
        if not self.crawling:
            try:
                block_index = create_index_from_blocks(blocks)
                chain_index = create_index_from_chain(chain, self.public_key.key_to_bin())
                assert sorted(block_index, key=lambda x: x[0]) == sorted(chain_index, key=lambda x: x[0])
            except AssertionError:
                logging.warning('%s: From blocks: %s', self.address, sorted(block_index, key=lambda x: x[0]))
                logging.warning('%s: From chain: %s', self.address, sorted(chain_index, key=lambda x: x[0]))
        with open(os.path.join('data', self.public_key.key_to_bin().encode('hex')[20:30] + '.dat'), 'w+') as f:
            f.write('%s %s\n' % (self.public_key.key_to_bin().encode('hex'),
                                 len(blocks)))
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
        self.dishonest = dishonest

        self.com.start(self.handle)

        self.register()

        self.loop = ioloop.IOLoop.current()
        self.loop.call_later(self.emulation_duration*self.emulation_step_length, self.unregister)
        self.loop.call_later(self.startup_time, self.get_agents)
        cb_step = ioloop.PeriodicCallback(self.step, self.emulation_step_length*1000)
        self.loop.call_later(self.startup_time + 5, cb_step.start)
        self.loop.start()

        self.write_data()
