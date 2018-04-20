#!/usr/bin/env python
"""
Main executable for running experiments.
"""

import argparse
import logging
from src.experiment_runner import ExperimentRunner

def main():
    """
    Parses the arguments and starts the experiment.
    """
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--config',
        type=argparse.FileType('r'),
        help='The experiment configuration file.'
    )

    args = parser.parse_args()

    runner = ExperimentRunner()
    runner.load_configuration(args.config)
    runner.run()



if __name__ == "__main__":
    main()
