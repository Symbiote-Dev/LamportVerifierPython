from eth_abi import encode_single
from web3 import Web3
from typing import List
import codecs
import re
import hashlib

def _pack(type: str, value, isArray: bool = False):
    if type == "address":
        if isArray:
            return value.rjust(32, b'\x00')
        return bytes.fromhex(value[2:])
    elif type == "string":
        return value.encode('utf-8')
    elif type == "bytes":
        return bytes.fromhex(value[2:])
    elif type == "bool":
        value = '0x01' if value else '0x00'
        if isArray:
            return bytes.fromhex(value[2:]).rjust(32, b'\x00')
        return bytes.fromhex(value[2:])

    regex_number = re.compile("^(u?int)([0-9]*)$")
    match = regex_number.match(type)
    if match:
        size = int(match.group(2) or "256")
        if isArray:
            size = 256
        value = int(value).to_bytes(size // 8, 'big')
        return value.rjust(size // 8, b'\x00')

    regex_bytes = re.compile("^bytes([0-9]+)$")
    match = regex_bytes.match(type)
    if match:
        size = int(match.group(1))
        if len(bytes.fromhex(value[2:])) != size:
            raise ValueError(f"invalid value for {type}")
        if isArray:
            return bytes.fromhex(value[2:] + '00' * (32 - size))
        return bytes.fromhex(value[2:])

    regex_array = re.compile("^(.*)\\[([0-9]*)\\]$")
    match = regex_array.match(type)
    if match and isinstance(value, list):
        baseType = match.group(1)
        count = int(match.group(2) or str(len(value)))
        if count != len(value):
            raise ValueError(f"invalid array length for {type}")
        result = []
        for val in value:
            result.append(_pack(baseType, val, True))
        return b''.join(result)

    raise ValueError("invalid type")

def solidity_pack(types: List[str], values: List) -> str:
    if len(types) != len(values):
        raise ValueError("wrong number of values; expected %s" % len(types))
    packed_values = []
    for t, v in zip(types, values):
        packed_values.append(_pack(t, v))
    concatenated = b''.join(packed_values)
    return '0x' + codecs.encode(concatenated, 'hex').decode()

def keccak256(types: List[str], values: List) -> str:
    return Web3.solidityKeccak(types, values).hex()

def sha256(types: List[str], values: List) -> str:
    packed = solidity_pack(types, values)[2:]
    return '0x' + hashlib.sha256(bytes.fromhex(packed)).hexdigest()
