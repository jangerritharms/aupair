"""
This module contains some helping functions which are not part of a class.
"""
from src.pyipv8.ipv8.attestation.trustchain.block import UNKNOWN_SEQ

def create_index_from_chain(chain, public_key):
    """
    Takes the full trustchain of an agent and creates an index in the format:
    [[public_key1, [seq1, seq2,...]][public_key2, [seq1, seq2,...]],...]
    """
    index_dict = {}
    for block in chain:
        if len(block.transaction) == 0:
            index_dict.setdefault(public_key, []).append(block.sequence_number)
        else:
            index_dict.setdefault(block.public_key, []).append(block.sequence_number)
            if block.transaction.get('transfer_up') or block.transaction.get('transfer_down'):
                transfer = {}
                if block.link_sequence_number != UNKNOWN_SEQ:
                    transfer = block.transaction['transfer_up']
                else:
                    transfer = block.transaction['transfer_down']
                for elem in transfer:
                    index_dict.setdefault(elem[0], []).extend(elem[1])

    return [[elem[0], sorted(list(set(elem[1])))] for elem in index_dict.items()]

def create_index_from_blocks(blocks):
    """
    Takes a set of blocks and creates an index.
    """
    index_dict = {}
    for block in blocks:
        index_dict.setdefault(block.public_key, []).append(block.sequence_number)

    return [[elem[0], sorted(list(set(elem[1])))] for elem in index_dict.items()]

def calculate_difference(own_index, other_index):
    """
    Takes two index objects and calculates the difference.
    """
    own_index = sorted(own_index, key = lambda x: x[0])
    other_index = sorted(other_index, key = lambda x: x[0])

    i = 0
    j = 0
    exchange = []
    while i < len(own_index) and j < len(other_index):
        own_key = own_index[i][0]
        other_key = other_index[j][0]

        if own_key == other_key:
            if own_index[i][1] != other_index[j][1]:
                diff = list(set(own_index[i][1]) - set(other_index[j][1]))
                if len(diff) > 0:
                    exchange.append([own_key, diff])
            i += 1
            j += 1
        elif own_key < other_key:
            exchange.append([own_key, own_index[i][1]])
            i += 1
        else:
            j += 1

    while i < len(own_index):
        own_key = own_index[i][0]
        exchange.append([own_key, own_index[i][1]])
        i += 1

    return exchange
