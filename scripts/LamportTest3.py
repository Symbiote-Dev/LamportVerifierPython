import lorem
import sys
import hashlib
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
from offchain.Types import LamportKeyPair, Sig, PubPair
from offchain.functions import hash_b, sign_hash, verify_signed_hash

gas_strategy = LinearScalingStrategy("60 gwei", "70 gwei", 1.1)

# if network.show_active() == "development":
gas_price(gas_strategy)

ITERATIONS = 3

'''
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
'''
import hashlib


def verify_u256(bits: int, sig: List[bytes], pub: List[List[bytes]]) -> bool:
    for i in range(256):
        index = 1 if ((bits & (1 << (255 - i))) > 0) else 0
        print(f"Index: {i}, Bit: {index}")
        print(f"Pub Value: {pub[i][index].hex()}")
        hashed_sig = hashlib.sha256(sig[i].encode()).digest()
        print(f"Hash: {hashed_sig.hex()}")
        if pub[i][index].hex() != hashed_sig.hex():
            return False
    return True




def encode_packed(*args):
    return b"".join([struct.pack(f"<{len(arg)}s", arg) for arg in args])
def main():
    lamport_test = LamportTest()
    # Convert all account objects to strings before passing them
    lamport_test.can_broadcast_message_via_broadcast2([str(acc) for acc in accounts])

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

        _contract.init(k.pkh)
        print("Contract initialized.")

        b1 = web3.eth.getBalance(accs[0])
        print(f"Balance before: {b1}")

        for i in range(ITERATIONS):
            print(f"Iteration {i+1}...")
            current_keys = k.current_key_pair()
            next_keys = k.get_next_key_pair()

            # Replace this:
            # expectedPKH = KeyTracker.pkh_from_public_key(current_keys.pub)
            # With this:
            expectedPKH = _contract.computePKH(current_keys.pub, {'from': str(accs[0])})
            currentPKH = _contract.getPKH()

            print(f"Expected PKH: {expectedPKH}")
            print(f"Current PKH: {currentPKH}")

            #expectedPKH = _contract.getPKH()
            if KeyTracker.pkh_from_public_key(current_keys.pub) == expectedPKH:
                print("Public Key Hash (PKH) check passed.")

            nextpkh = KeyTracker.pkh_from_public_key(next_keys.pub)
            nextpkh_bytes = bytes.fromhex(nextpkh[2:])

            messageToBroadcast = lorem.sentence()
            messageToBroadcast_bytes = messageToBroadcast.encode('utf-8')

            print(nextpkh)
            print("first", messageToBroadcast_bytes)
            message_packed = encode_packed(messageToBroadcast_bytes, nextpkh_bytes)
            print("second", message_packed)
            keccak_hash = hashlib.sha3_256(message_packed).digest()
            print("third", keccak_hash)
            hex_hash = keccak_hash.hex()
            print("fourth", hex_hash)
            integer_hash = int(hex_hash, 16)
            print("fifth", integer_hash)

         
            #msg_hash_bin = int(keccak_hash.hex(), 16)

            #msg_hash_int = int(str(keccak_hash), 10)  # Convert the string to an integer with base 10

            #msg_hash_bin = format(msg_hash_int, '0256b')

            #print()
            #messageToBroadcast_bytes = bytes(messageToBroadcast, 'utf-8')
            #print(messageToBroadcast)
            #messageToBroadcast_bytes = messageToBroadcast.encode('utf-8')
            #print(messageToBroadcast_bytes)
            #temp = struct.pack(f"{len(messageToBroadcast_bytes)}s", messageToBroadcast_bytes)
            #nextpkh_bytes = bytes.fromhex(nextpkh[2:])
            #packed = temp + nextpkh_bytes

            #messageToBroadcast_bytes = encode_single('string', messageToBroadcast)
            #packed_message = encode_single('string', messageToBroadcast_bytes)# + nextpkh.encode('utf-8'))
            #keccak_hash = keccak.new(digest_bits=256)
            #keccak_hash.update(packed_message)
            #result = keccak_hash.hexdigest()
            #callhash = hash_b(message_packed)

            #packed = web3.solidityKeccak(['string', 'bytes32'], [messageToBroadcast, nextpkh])
            #packed_int = int(packed.hex(), 16)
            #callhash = hash_b(encode_hex(packed))
            #callhash = int.from_bytes((result), byteorder='big')
            #callhash = int.from_bytes(bytes.fromhex(hash_b(encode_hex(packed))), byteorder='big')


            sig = sign_hash(hex_hash, current_keys.pri) # first arg is keccak'd (hex'd and int'd)
            sentsig = list(map(lambda s: f"0x{s}", sig))
            #print(sig)
            print("OOOOOOOOOOOOOO")
            #print(sentsig)
            

            is_valid_sig = verify_u256(integer_hash, sig, current_keys.pub)
            if not is_valid_sig:
                print("Signature validity check failed.")
                sys.exit()
            else:
                print("Signature validity check passed.")

            # Make sure the account is passed as a string
            _contract.broadcast(
                messageToBroadcast,
                current_keys.pub,
                nextpkh,
                list(map(lambda s: f"0x{s}", sig)),
                {'from': str(accs[0])}
            )
            print("Broadcast completed.")

        b2 = web3.eth.getBalance(accs[0])
        print(f"Balance after: {b2}")

        b_delta = b1 - b2
        print(f"Balance delta: {b_delta}")

        datum = {
            "ts": int(time.time()),
            "avg_gas": str(b_delta / ITERATIONS),
            "iterations": ITERATIONS,
        }

        with open('gas_data2.json', 'r') as json_file:
            gas_data = json.load(json_file)

        gas_data.append(datum)
        print("Appending data to 'gas_data'...")

        with open('gas_data.json', 'w') as json_file:
            json.dump(gas_data, json_file, indent=2)
        print("Data saved to 'gas_data.json'.")

        print("'can_broadcast_message_via_broadcast2' completed.")