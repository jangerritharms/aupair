# AuPair: Strategyproof dissemination mechanism

This is the standalone implementation of the pairwise auditing mechanism for
strategyproof information dissemination in distributed transaction based reputation
systems.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

The runner takes a configuration file as input an performs the experiment defined
in that configuration. The configuration files contain information such as the 
number of nodes to spawn, the length of the experiment and the data to output.

```bash
./run.py --config configs/small.json
```
