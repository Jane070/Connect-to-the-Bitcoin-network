import struct
import hashlib
import time
import socket
from datetime import datetime

MAGIC_NUMBER = 0xD9B4BEF9


def create_version_payload():
    version = struct.pack('<I', 70015)  # Protocol version
    services = struct.pack('<Q', 1)  # Node services
    timestamp = struct.pack('<q', int(time.time()))
    addr_recv = struct.pack('<Q', 1) + b'\x00' * 10 + b'\xff\xff' + socket.inet_aton("127.0.0.1") + struct.pack('>H',
                                                                                                                8333)
    addr_from = struct.pack('<Q', 1) + b'\x00' * 10 + b'\xff\xff' + socket.inet_aton("127.0.0.1") + struct.pack('>H',
                                                                                                                8333)
    nonce = struct.pack('<Q', 0)  # Random nonce
    user_agent_bytes = b'\x00'  # User agent (empty)
    start_height = struct.pack('<i', 0)  # Start height
    relay = b'\x00'  # Relay
    return version + services + timestamp + addr_recv + addr_from + nonce + user_agent_bytes + start_height + relay


def parse_message(data):
    magic = struct.unpack('<L', data[:4])[0]
    command = data[4:16].strip(b'\x00').decode()
    length = struct.unpack('<L', data[16:20])[0]
    checksum = data[20:24]
    payload = data[24:24 + length]
    return {'magic': magic, 'command': command, 'length': length, 'checksum': checksum, 'payload': payload}


def decode_varint(data):
    n = data[0]
    if n < 0xfd:
        return n, data[1:]
    elif n == 0xfd:
        return struct.unpack('<H', data[1:3])[0], data[3:]
    elif n == 0xfe:
        return struct.unpack('<I', data[1:5])[0], data[5:]
    else:
        return struct.unpack('<Q', data[1:9])[0], data[9:]


def parse_block(payload):
    block_header = payload[:80]
    version = struct.unpack('<I', block_header[:4])[0]
    prev_block = block_header[4:36].hex()
    merkle_root = block_header[36:68].hex()
    timestamp = struct.unpack('<I', block_header[68:72])[0]
    bits = struct.unpack('<I', block_header[72:76])[0]
    nonce = struct.unpack('<I', block_header[76:80])[0]
    human_readable_time = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    transaction_count, tx_data = decode_varint(payload[80:])
    transactions = []

    offset = 80 + len(tx_data)
    for _ in range(transaction_count):
        tx_length, tx_data = decode_varint(payload[offset:])
        transactions.append(payload[offset:offset + tx_length].hex())
        offset += tx_length

    return {
        'version': version,
        'prev_block': prev_block,
        'merkle_root': merkle_root,
        'timestamp': human_readable_time,
        'bits': bits,
        'nonce': nonce,
        'transactions': transactions
    }


def verify_block_hash(block_header, expected_hash):
    actual_hash = hashlib.sha256(hashlib.sha256(block_header).digest()).digest()[::-1]
    return actual_hash.hex() == expected_hash
