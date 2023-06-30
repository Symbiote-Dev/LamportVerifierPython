import os
import json
from typing import List
from web3 import Web3
from offchain.Types import *
from offchain.functions import *
from web3.exceptions import InvalidAddress
from eth_utils import keccak, encode_hex


# Assuming the imported classes and functions from the previous translation:
# RandPair, PubPair, LamportKeyPair, mk_key_pair, hash_b

class KeyTracker:
    def __init__(self, _name: str = 'default'):
        self.private_keys: List[List[RandPair]] = []
        self.public_keys: List[List[PubPair]] = []
        self.name: str = _name
        self.w3 = Web3()  # Create an instance of Web3

    @staticmethod
    #def pkh_from_public_key(pub: List[PubPair]) -> str:
    #    packed_pub = Web3.soliditySha3(['bytes32[2][256]'], [pub])
    #    return hash_b(packed_pub.hex())
    def pkh_from_public_key(pub: List[PubPair]) -> str:
        packed_pub = Web3.solidityKeccak(['bytes32[2][256]'], [pub])
        return encode_hex(packed_pub)

    @property
    def pkh(self):
        return KeyTracker.pkh_from_public_key(self.current_key_pair().pub)

    def save(self, trim: bool = False):
        if trim:
            _private_keys = self.private_keys[-3:]
            _public_keys = self.public_keys[-3:]
        else:
            _private_keys = self.private_keys
            _public_keys = self.public_keys

        data = {
            'privateKeys': _private_keys,
            'publicKeys': _public_keys,
            'name': self.name
        }
        with open(f'keys/{self.name}.json', 'w') as file:
            json.dump(data, file, indent=2)

    @staticmethod
    def load(name: str):
        with open(f'keys/{name}.json', 'r') as file:
            data = json.load(file)
        key_tracker = KeyTracker()
        key_tracker.__dict__.update(data)
        return key_tracker

    def get_next_key_pair(self) -> LamportKeyPair:
        key_pair = mk_key_pair()
        pri = key_pair.pri
        pub = key_pair.pub
        self.private_keys.append(pri)
        self.public_keys.append(pub)
        return LamportKeyPair(pri=pri, pub=pub)


    def current_key_pair(self) -> LamportKeyPair:
        if not self.private_keys:
            return self.get_next_key_pair()
        return LamportKeyPair(pri=self.private_keys[-1], pub=self.public_keys[-1])

    def previous_key_pair(self) -> LamportKeyPair:
        if len(self.private_keys) < 2:
            raise ValueError('no previous key pair')
        return LamportKeyPair(pri=self.private_keys[-2], pub=self.public_keys[-2])
