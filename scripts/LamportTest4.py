import lorem
import sys
from itertools import chain
import random
import hashlib
from web3 import Web3
from brownie import web3, accounts, Wei, LamportTest2
from brownie.network import gas_price
from brownie.network.gas.strategies import LinearScalingStrategy
from eth_utils import encode_hex #, encode_single
from eth_abi import encode_single
from Crypto.Hash import keccak
from typing import List
import json
import time
from typing import List
import struct
from offchain.KeyTracker import KeyTracker
from offchain.soliditypack import solidity_pack
from offchain.Types import LamportKeyPair, Sig, PubPair
from offchain.functions import hash_b, sign_hash, verify_signed_hash
from eth_abi import encode_abi

gas_strategy = LinearScalingStrategy("60 gwei", "70 gwei", 1.1)

# if network.show_active() == "development":
gas_price(gas_strategy)

ITERATIONS = 3


def verify_u256(bits: int, sig: List[bytes], pub: List[List[bytes]]) -> bool:
    for i in range(256):
        index = 1 if ((bits & (1 << (255 - i))) > 0) else 0
        print(f"Index: {i}, Bit: {index}")
        print(f"Pub Value: {pub[i][index]}")
        print(f"Hash: {hashlib.sha256(sig[i].encode()).digest()}")
        index = 1 if ((bits & (1 << (255 - i))) > 0) else 0
        if pub[i][index] != hashlib.sha256(sig[i].encode()).digest():
            return False
    return True

import hashlib

def encode_packed(*args):
    return b"".join([struct.pack(f"<{len(arg)}s", arg) for arg in args])
def main():
    lamport_test = LamportTest()
    # Convert all account objects to strings before passing them
    lamport_test.can_broadcast_message_via_broadcast2([str(acc) for acc in accounts])
    lamport_test.can_broadcast_message_via_broadcast_with_number([str(acc) for acc in accounts])
    lamport_test.can_broadcast_message_via_broadcast_with_number_and_address([str(acc) for acc in accounts])



class LamportTest:
    def __init__(self):
        print("Initializing LamportTest...")
        self.contract = LamportTest2

    def can_broadcast_message_via_broadcast2(self, accs):
        print("Running 'can_broadcast_message_via_broadcast2'...")

        print(f"hash_b(0): {hash_b('0x00')}")
        # Make sure the account is passed as a string
        _contract = self.contract.deploy({'from': str(accs[0])})
        print("Contract deployed.")
        
        k = KeyTracker()
        print("KeyTracker initialized.")

        _contract.init(k.pkh[2:])
        print(k.pkh[2:], "Contract initialized.")

        b1 = web3.eth.getBalance(accs[0])
        print(f"Balance before: {b1}")

        for i in range(ITERATIONS):
            print(f"Iteration {i+1}...")
            current_keys = k.current_key_pair()
            next_keys = k.get_next_key_pair()

            
            expectedPKH = KeyTracker.pkh_from_public_key(current_keys.pub)
            currentPKH = _contract.getPKH()

            print(f"Expected PKH: {expectedPKH}")
            print(f"Current PKH: {currentPKH}")

            if KeyTracker.pkh_from_public_key(current_keys.pub) == expectedPKH:
                print("Public Key Hash (PKH) check passed.")

            # contract call message
            messageToBroadcast = lorem.sentence()


            # 
            nextpkh = KeyTracker.pkh_from_public_key(next_keys.pub)
            temp = solidity_pack(['string'], [messageToBroadcast])
            packed_message = solidity_pack(['bytes', 'bytes32'], [temp, nextpkh])
        
            callhash = hash_b(packed_message)

            sig = sign_hash(callhash, current_keys.pri) 

            is_valid_sig = verify_signed_hash(callhash, sig, current_keys.pub)
            if not is_valid_sig:
                print("Signature validity check failed.")
                sys.exit()
            else:
                print("Signature validity check passed.")
        
            print("next public key:", nextpkh[2:])

            # Make sure the account is passed as a string
            _contract.broadcast(
                messageToBroadcast,
                current_keys.pub,
                nextpkh[2:],
                list(map(lambda s: f"0x{s}", sig)),
                {'from': str(accs[0])}
            )
            print("Broadcast completed.")

            # Listen for the 'VerificationFailed' event
            verification_failed_filter = _contract.events.VerificationFailed.createFilter(fromBlock='latest')
            for event in verification_failed_filter.get_all_entries():
                hashed_data = event['args']['hashedData']
                print(f"Verification failed for hashed data: {hashed_data}")

            # Listen for the 'LogLastCalculatedHash' event
            last_calculated_hash_filter = _contract.events.LogLastCalculatedHash.createFilter(fromBlock='latest')
            for event in last_calculated_hash_filter.get_all_entries():
                hash_value = event['args']['hash']
                print(f"Last calculated hash: {hash_value}")

            # This is pulling public key hash data from LamportBase.sol
            pkh_updated_filter = _contract.events.PkhUpdated.createFilter(fromBlock='latest')
            for event in pkh_updated_filter.get_all_entries():
                previous_pkh = event['args']['previousPKH']
                new_pkh = event['args']['newPKH']
                print(f"Previous PKH: {previous_pkh}, New PKH: {new_pkh}")
            
            # message with number event filter


            # Create the filter
            message_filter = _contract.events.Message.createFilter(fromBlock='latest')

            # Get all entries from the "Message" event
            for event in message_filter.get_all_entries():
                message = event['args']['message']
                print(f"Message: {message}")


        b2 = web3.eth.getBalance(accs[0])
        print(f"Balance after: {b2}")

        b_delta = b1 - b2
        print(f"Balance delta: {b_delta}")

        datum = {
            "ts": int(time.time()),
            "avg_gas": str(b_delta / ITERATIONS),
            "iterations": ITERATIONS,
        }

        with open('gas_data2.json', 'a+') as json_file:
            try:
                gas_data = json.load(json_file)
            except json.JSONDecodeError:
                gas_data = {}

        gas_data.update(datum)
        print("Appending data to 'gas_data'...")

        with open('gas_data2.json', 'w') as json_file:
            json.dump(gas_data, json_file, indent=2)
        print("Data saved to 'gas_data2.json'.")

        print("'can_broadcast_message_via_broadcast2' completed.")

    def can_broadcast_message_via_broadcast_with_number(self, accs):
        print("Running 'can_broadcast_message_via_broadcast_with_number'...")

        _contract = self.contract.deploy({'from': str(accs[0])})
        print("Contract deployed.")
        
        k = KeyTracker()
        print("KeyTracker initialized.")

        _contract.init(k.pkh[2:])
        print(k.pkh[2:], "Contract initialized.")

        for i in range(ITERATIONS):
            print(f"Iteration {i+1}...")
            current_keys = k.current_key_pair()
            next_keys = k.get_next_key_pair()

            expectedPKH = KeyTracker.pkh_from_public_key(current_keys.pub)
            currentPKH = _contract.getPKH()

            print(f"Expected PKH: {expectedPKH}")
            print(f"Current PKH: {currentPKH}")

            if KeyTracker.pkh_from_public_key(current_keys.pub) == expectedPKH:
                print("Public Key Hash (PKH) check passed.")

            nextpkh = KeyTracker.pkh_from_public_key(next_keys.pub)

            messageToBroadcast = lorem.sentence()
            numToBroadcast = random.randint(0, 1000000)

            temp = solidity_pack(['string', 'uint256'], [messageToBroadcast, numToBroadcast])
            packed_message = solidity_pack(['bytes', 'bytes32'], [temp, nextpkh])

            callhash = hash_b(packed_message)
            sig = sign_hash(callhash, current_keys.pri)

            is_valid_sig = verify_signed_hash(callhash, sig, current_keys.pub)
            if not is_valid_sig:
                print("Signature validity check failed.")
                sys.exit()
            else:
                print("Signature validity check passed.")

            print("next public key:", nextpkh[2:])

            _contract.broadcastWithNumber(
                messageToBroadcast,
                numToBroadcast,
                current_keys.pub,
                nextpkh[2:],
                list(map(lambda s: f"0x{s}", sig)),
                {'from': str(accs[0])}
            )
            print("BroadcastWithNumber completed.")

        print("'can_broadcast_message_via_broadcast_with_number' completed.")

        message_with_number_filter = _contract.events.MessageWithNumber.createFilter(fromBlock='latest')

        for event in message_with_number_filter.get_all_entries():
            message = event['args']['message']
            number = event['args']['number']
            print(f"Message: {message}, Number: {number}")
    
    def can_broadcast_message_via_broadcast_with_number_and_address(self, accs):
        print("Running 'can_broadcast_message_via_broadcast_with_number_and_address'...")

        _contract = self.contract.deploy({'from': str(accs[0])})
        print("Contract deployed.")
        
        k = KeyTracker()
        print("KeyTracker initialized.")

        _contract.init(k.pkh[2:])
        print(k.pkh[2:], "Contract initialized.")

        for i in range(ITERATIONS):
            print(f"Iteration {i+1}...")
            current_keys = k.current_key_pair()
            next_keys = k.get_next_key_pair()

            expectedPKH = KeyTracker.pkh_from_public_key(current_keys.pub)
            currentPKH = _contract.getPKH()

            print(f"Expected PKH: {expectedPKH}")
            print(f"Current PKH: {currentPKH}")

            if KeyTracker.pkh_from_public_key(current_keys.pub) == expectedPKH:
                print("Public Key Hash (PKH) check passed.")

            nextpkh = KeyTracker.pkh_from_public_key(next_keys.pub)

            messageToBroadcast = lorem.sentence()
            numToBroadcast = random.randint(0, 1000000)
            addressToBroadcast = accs[numToBroadcast % len(accs)]

            temp = solidity_pack(['string', 'uint256', 'address'], [messageToBroadcast, numToBroadcast, addressToBroadcast])
            packed_message = solidity_pack(['bytes', 'bytes32'], [temp, nextpkh])

            callhash = hash_b(packed_message)
            sig = sign_hash(callhash, current_keys.pri)

            is_valid_sig = verify_signed_hash(callhash, sig, current_keys.pub)
            if not is_valid_sig:
                print("Signature validity check failed.")
                sys.exit()
            else:
                print("Signature validity check passed.")

            print("next public key:", nextpkh[2:])

            _contract.broadcastWithNumberAndAddress(
                messageToBroadcast,
                numToBroadcast,
                addressToBroadcast,
                current_keys.pub,
                nextpkh[2:],
                list(map(lambda s: f"0x{s}", sig)),
                {'from': str(accs[0])}
            )
            print("BroadcastWithNumberAndAddress completed.")

        print("'can_broadcast_message_via_broadcast_with_number_and_address' completed.")
        
        message_with_number_and_address_filter = _contract.events.MessageWithNumberAndAddress.createFilter(fromBlock='latest')

        # Get all entries from the "MessageWithNumberAndAddress" event
        for event in message_with_number_and_address_filter.get_all_entries():
            message = event['args']['message']
            number = event['args']['number']
            addr = event['args']['addr']
            print(f"Message: {message}, Number: {number}, Address: {addr}")
