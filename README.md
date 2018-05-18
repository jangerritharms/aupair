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

## Process

Pairwise auditing leads to validation and dissemination of data. It works in the following way when
considering agents Alice (A) and Bob (B).

* A requests data from B, therefore B would like to check the trustworthiness of A
* B requests full chain of A, shares own chain
* A shares chain, verifies B's chain and sends difference, creates block
* B checks the chain and if complete calculates the difference in blocks, which he sends to A, signing block
* B calculates trustworthiness of A

We are protecting against double-spending, the self-
