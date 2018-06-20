"""
Module defining the experiment runner class.
"""
import os
import logging
import json
import matplotlib.pyplot as plt
from multiprocessing import Process

import src.analysis.agent
from src.agent.base import BaseAgent
from src.agent.protect import ProtectAgent
from src.agent.simple_protect import ProtectSimpleAgent
from src.agent.bad_chain import BadChainProtectAgent
from src.discovery import DiscoveryServer, spawn_discovery_server

from src.pyipv8.ipv8.attestation.trustchain.database import TrustChainDB


class ExperimentRunner(object):
    """
    The experiment runner loads a configuration and executes the experiment.
    It starts subprocesses of the discovery server and each agent. The experiment
    runner waits until the agent processes finish.
    """

    def __init__(self):
        """
        Creates a new ExperimentRunner.
        """
        self.options = {}
        self.agent_processes = []

    def load_configuration(self, config):
        """
        Reads the configuration file and stores options in self.options.

        :param config:
        """
        logging.debug("Opening config file: %s", config)
        FORMAT = '%(address)s %(message)s'
        logging.basicConfig(format=FORMAT)
        db_logger = logging.getLogger("Database")
        db_logger.propagate = False
        logging.disable(logging.INFO)
        contents = config.read()
        self.options = json.loads(contents)

    def analysis(self):
        """
        Analyzes the results of the experiment.
        """
        files = os.listdir('data/')
        files = [f for f in files if f[-4:] == '.dat']

        agents = []
        honest_agents = []
        dishonest_agents = []
        for db_file in files:
            agent = src.analysis.agent.Agent.from_file(os.path.join('data', db_file))
            agents.append(agent)
            if agent.info.type == "ProtectSimple":
                honest_agents.append(agent)
            elif agent.info.type == "BadChain":
                dishonest_agents.append(agent)

        keys = [agent.info.public_key.as_readable() for agent in agents]
        honest_transactions = [agent.transactions_blocks() for agent in honest_agents]
        dishonest_transactions = [agent.transactions_blocks() for agent in dishonest_agents]
        print len(dishonest_transactions)

        p1 = plt.bar(range(len(honest_agents)), honest_transactions, 0.35, color="#57a773")
        p2 = plt.bar(range(len(honest_agents), len(honest_agents) + len(dishonest_agents)),
                     dishonest_transactions, 0.35, color="#3f88c5")

        plt.title('Database view')
        plt.xlabel('Agent by public key')
        plt.xlim([0, len(agents)])
        plt.xticks(range(len(agents)), keys, rotation="vertical")
        plt.ylabel('Number of transaction')
        plt.legend((p1, p2), ("Honest agents", "Dishonest agents"))
        plt.tight_layout()
        plt.show()

    def run(self):
        """
        Starts the discovery server and all agent processes. Then waits until
        the processes reach the end of the emulation. The number of cycles to
        wait for are specified in the configuration file.
        """
        # delete old database files from previous experiments
        files = os.listdir('sqlite/')
        for db_file in files:
            file_path = os.path.join('sqlite', db_file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(e)

        files = os.listdir('data/')
        for db_file in files:
            file_path = os.path.join('data', db_file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(e)

        discovery = DiscoveryServer()
        discovery.configure(self.options)
        discovery_process = Process(target=spawn_discovery_server, args=(discovery, ))
        discovery_process.start()

        for _ in range(self.options['honest_nodes']):
            agent = ProtectSimpleAgent()
            next_port = self.options['node_port_range_begin'] + len(self.agent_processes)
            agent.setup(self.options, next_port)
            agent_process = Process(target=agent.run)
            agent_process.start()
            self.agent_processes.append(agent_process)

        for _ in range(self.options['dishonest_nodes']):
            agent = BadChainProtectAgent()
            next_port = self.options['node_port_range_begin'] + len(self.agent_processes)
            agent.setup(self.options, next_port)
            agent_process = Process(target=agent.run)
            agent_process.start()
            self.agent_processes.append(agent_process)

        for process in self.agent_processes:
            process.join()

        discovery_process.join()
        self.analysis()
