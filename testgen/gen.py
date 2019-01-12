from web3.auto import w3
from functools import reduce
import json
import random

def random_bytes(count):
    return [random.randint(0, 255) for _ in range(0, count)]

def random_hex(hex_len):
    hexstr = ""

    for b in random_bytes(hex_len):
        h = hex(b)[2:]
        if len(h) == 1:
            h = '0' + h
        hexstr += h

    return hexstr.upper()

def to_hex(data):
    hexstr = ""

    for b in data:
        h = hex(b)[2:]
        if len(h) == 1:
            h = '0' + h
        hexstr += h

    return hexstr.upper()

def random_tx(len_data, private_key, chain_id):
    data = random_bytes(random.randint(0, 48))

    tx = {
        'to': '0xF0109fC8DF283027b6285cc889F5aA624EaC1F55',#'0x%s' % random_hex(20),
        'value': random.randint(0, 10000000000),
        'gas': random.randint(0, 10000000000),
        'gasPrice': random.randint(0, 234567897654321),
        'nonce': random.randint(0, 200),
        'chainId': chain_id,
        'data': to_hex(data)
    }

    signed = w3.eth.account.signTransaction(tx, private_key=private_key)

    #print(signed.rawTransaction)
    #print(signed.r)
    #print(signed.s)
    #print((signed.rawTransaction.hex()))
    #print(signed)

    new_tx = dict()

    del tx['chainId']

    tx['value']= hex(tx['value']);
    tx['gas'] = hex(tx['gas']);
    tx['gasPrice'] = hex(tx['gasPrice']);
    tx['nonce'] = hex(tx['nonce']);
    tx['data'] = data

    return [tx, {'private_key': private_key, 'signed': [b for b in signed.rawTransaction]}]

HOWMANY = 100

txs = []

for i in range(0, HOWMANY):
    tx = random_tx(i * 5, '0xe331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109', 0)
    txs.append(tx)

print(json.dumps(txs, indent=2))
