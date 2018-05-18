"""
Module defining the experiment runner class.
"""
import os
import logging
import json
import matplotlib.pyplot as plt
from multiprocessing import Process

import src.analysis.agent
from src.agent import Agent
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
        contents = config.read()
        self.options = json.loads(contents)

    def analysis(self):
        """
        Analyzes the results of the experiment.
        """
        files = os.listdir('data/')
        files = [f for f in files if f[-4:] == '.dat']

        agents = []
        for db_file in files:
            agent = src.analysis.agent.Agent.from_file(os.path.join('data', db_file))
            agents.append(agent)

        stack = [[agent.transactions_blocks() for agent in agents],
                 [agent.exchange_blocks() for agent in agents],
                 [agent.foreign_blocks() for agent in agents]]
        plt.stackplot(range(len(agents)),
                      *stack,
                      labels=['transactions', 'exchange', 'foreign'],
                      baseline='zero')
        plt.title('Database view')
        plt.xlabel('Agent')
        plt.ylabel('Number of blocks')
        plt.legend(loc=2)
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
            agent = Agent()
            next_port = self.options['node_port_range_begin'] + len(self.agent_processes)
            agent.configure(self.options, next_port)
            agent_process = Process(target=agent.run)
            agent_process.start()
            self.agent_processes.append(agent_process)

        for _ in range(self.options['dishonest_nodes']):
            agent = Agent()
            next_port = self.options['node_port_range_begin'] + len(self.agent_processes)
            agent.configure(self.options, next_port)
            agent_process = Process(target=agent.run, args=(True, ))
            agent_process.start()
            self.agent_processes.append(agent_process)

        for process in self.agent_processes:
            process.join()

        discovery_process.join()
        self.analysis()
