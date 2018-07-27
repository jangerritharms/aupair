"""
Module defining the experiment runner class.
"""
import os
import logging
import json
from multiprocessing import Process

from src.discovery import DiscoveryServer, spawn_discovery_server
from src.analysis.analyzer import Analyzer
from src.agent.base import BaseAgent
from src.agent.protect import ProtectAgent
from src.agent.simple_protect import ProtectSimpleAgent
from src.agent.no_verification import NoVerificationAgent
from src.agent.double_spend import DoubleSpendAgent
from src.agent.bad_chain import BadChainProtectAgent
from src.agent.advanced_protect import ProtectAdvancedAgent
from src.agent.empty_exchanges import EmptyExchangeAgent
from src.agent.self_request import SelfRequestAgent

from src.pyipv8.ipv8.attestation.trustchain.database import TrustChainDB

AGENT_CLASSES = [
    BaseAgent,
    # ProtectAgent,
    ProtectSimpleAgent,
    BadChainProtectAgent,
    NoVerificationAgent,
    DoubleSpendAgent,
    ProtectAdvancedAgent,
    EmptyExchangeAgent,
    SelfRequestAgent
]
AGENT_CLASS_TYPES = {agent_cls._type: agent_cls for agent_cls in AGENT_CLASSES}


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
        logging.disable(logging.DEBUG)
        contents = config.read()
        self.options = json.loads(contents)

    def analysis(self, plot, data_directory='data/'):
        """
        Analyzes the results of the experiment.
        """
        analyzer = Analyzer(data_directory)

        analyzer.run_analysis(plot)

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

        if not os.path.exists(self.options['data_directory']):
            try:
                os.makedirs(self.options['data_directory'])
            except OSError as exc: # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

        files = os.listdir(self.options['data_directory'])
        for db_file in files:
            file_path = os.path.join(self.options['data_directory'], db_file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(e)

        discovery = DiscoveryServer()
        discovery.configure(self.options)
        discovery_process = Process(target=spawn_discovery_server, args=(discovery, ))
        discovery_process.start()

        for group in self.options['node_groups']:
            for _ in range(group['count']):
                agent = AGENT_CLASS_TYPES[group['type']]()
                next_port = self.options['node_port_range_begin'] + len(self.agent_processes)
                agent.setup(self.options, next_port)
                agent_process = Process(target=agent.run)
                agent_process.start()
                self.agent_processes.append(agent_process)

        for process in self.agent_processes:
            process.join()

        discovery_process.join()
        self.analysis()
