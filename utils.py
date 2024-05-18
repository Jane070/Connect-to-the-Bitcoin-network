import struct
import hashlib
import time
import socket
from datetime import datetime

MAGIC_NUMBER = 0xD9B4BEF9


def create_version_payload():
    # Constructing a version payload for initiating communication with a Bitcoin node
    version = struct.pack('<I', 70015)  # Protocol version
    services = struct.pack('<Q', 1)  # Node services
    timestamp = struct.pack('<q', int(time.time()))
    # Receiver address (localhost for demonstration purposes)
    addr_recv = struct.pack('<Q', 1) + b'\x00' * 10 + b'\xff\xff' + socket.inet_aton("127.0.0.1") + struct.pack('>H',
                                                                                                        8333)
    # Sender address (localhost for demonstration purposes)
    addr_from = struct.pack('<Q', 1) + b'\x00' * 10 + b'\xff\xff' + socket.inet_aton("127.0.0.1") + struct.pack('>H',
                                                                                                                8333)
    nonce = struct.pack('<Q', 0)  # Random nonce
    user_agent_bytes = b'\x00'  # User agent (empty)
    start_height = struct.pack('<i', 0)  # Start height
    relay = b'\x00'  # Relay
    return version + services + timestamp + addr_recv + addr_from + nonce + user_agent_bytes + start_height + relay


def parse_message(data):
    # Parse the received message from the Bitcoin node
    magic = struct.unpack('<L', data[:4])[0]
    command = data[4:16].strip(b'\x00').decode()
    length = struct.unpack('<L', data[16:20])[0]
    checksum = data[20:24]
    payload = data[24:24 + length]
    return {'magic': magic, 'command': command, 'length': length, 'checksum': checksum, 'payload': payload}


def decode_varint(data):
    # Decode a variable integer from the given byte stream
    n = data[0]
    if n < 0xfd:
        return n, data[1:]
    elif n == 0xfd:
        return struct.unpack('<H', data[1:3])[0], data[3:]
    elif n == 0xfe:
        return struct.unpack('<I', data[1:5])[0], data[5:]
    else:
        return struct.unpack('<Q', data[1:9])[0], data[9:]


# Function to send a message to the Bitcoin node
def send_message(sock, command, payload):
    magic = struct.pack('<L', 0xD9B4BEF9) # Magic value for Bitcoin network
    command = command.ljust(12, '\x00').encode('utf-8') # Command string padded to 12 bytes
    length = struct.pack('<I', len(payload)) # Length of payload
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] # Checksum of payload
    message = magic + command + length + checksum + payload # Constructing the message
    print(f"Sending message: {message.hex()}")
    sock.sendall(message)
    print(f"Sent {command.strip().decode()} message")

# Function to send a pong message in response to a ping message from the node
def send_pong(sock, nonce):
    print("Sending pong message...")
    send_message(sock, 'pong', nonce)
    print("Sent pong message in response to ping")

def format_timestamp(timestamp):
    # Format a UNIX timestamp into a human-readable format
    return datetime.utcfromtimestamp(timestamp).strftime('%dst %B %Y at %H:%M')


