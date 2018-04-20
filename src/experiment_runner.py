"""
Module defining the experiment runner class.
"""
import logging
import json
from multiprocessing import Process

from src.agent import Agent, spawn_agent
from src.discovery import DiscoveryServer, spawn_discovery_server

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
        contents = config.read()
        self.options = json.loads(contents)

    def run(self):
        """
        Starts the discovery server and all agent processes. Then waits until
        the processes reach the end of the emulation. The number of cycles to
        wait for are specified in the configuration file.
        """
        discovery = DiscoveryServer()
        discovery.configure(self.options)
        discovery_process = Process(target=spawn_discovery_server, args=(discovery, ))
        discovery_process.start()

        for _ in range(self.options['honest_nodes']):
            agent = Agent()
            next_port = self.options['node_port_range_begin'] + len(self.agent_processes)
            agent.configure(self.options, next_port)
            agent_process = Process(target=spawn_agent, args=(agent, ))
            agent_process.start()
            self.agent_processes.append(agent_process)


        for process in self.agent_processes:
            process.join()

        discovery_process.join()
