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
        'command'
    )
    parser.add_argument(
        '--config',
        type=argparse.FileType('r'),
        help='The experiment configuration file.'
    )
    parser.add_argument(
        '--data',
        help='Directory of data files'
    )
    parser.add_argument(
        '--plot',
        help='Which plot to show'
    )

    args = parser.parse_args()

    runner = ExperimentRunner()
    if args.command == 'execute':
        runner.load_configuration(args.config)
        runner.run()
    elif args.command == 'analyze':
        runner.analysis(args.plot, args.data)



if __name__ == "__main__":
    main()
