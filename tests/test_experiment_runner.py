import unittest
from src.experiment_runner import ExperimentRunner

class TestExperimentRunner(unittest.TestCase):

    def test1(self):
        "Properly loads a configuration file."
        e = ExperimentRunner()
        with open('tests/resources/test_config.json', 'r') as config:
            e.load_configuration(config)
            self.assertEquals(e.options['honest_nodes'],2)

    def test2(self):
        "Spawns an agent."
        e = ExperimentRunner()
        e.spawnAgent()
