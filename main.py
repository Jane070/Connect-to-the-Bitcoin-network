import socket
import time
import hashlib
import struct
from utils2 import create_version_payload, parse_message, parse_block, verify_block_hash, decode_varint


def get_node_ip(domain='seed.bitcoin.sipa.be'):
    return socket.gethostbyname_ex(domain)[2][0]


def connect_to_node(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, 8333))  # Bitcoin default port is 8333

        version_payload = create_version_payload()
        print(f"Sending version message: {version_payload.hex()}")

        send_message(sock, 'version', version_payload)

        response = receive_message(sock)  # Expecting version message

        if response and response.get('command') == 'version':
            print(f"Received version message: {response}")

            send_message(sock, 'verack', b'')

            print("Sent verack message")
            return sock

            # response_verack = receive_message(sock)  # Expecting verack message

            # if response_verack and response_verack.get('command') == 'verack':
            #     print("Received verack message.")

            #     return sock
            # else:
            #     print(f"Expected verack message but received: {response_verack}")
        else:
            print(f"Expected version message but received: {response}")
        
        sock.close()
        print("Failed to complete handshake with node.")
        return None
    except Exception as e:
        print(f"Error connecting to node: {e}")
        return None


def send_message(sock, command, payload):
    magic = struct.pack('<L', 0xD9B4BEF9)
    command = command.ljust(12, '\x00').encode('utf-8')
    length = struct.pack('<I', len(payload))
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    message = magic + command + length + checksum + payload
    print(f"Sending message: {message.hex()}")
    sock.sendall(message)
    print(f"Sent {command.strip().decode()} message")


def receive_message(sock):
    def recvall(sock, n):
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    try:
        magic = recvall(sock, 4)
        if not magic:
            return None
        command = recvall(sock, 12)
        if not command:
            return None
        length = recvall(sock, 4)
        if not length:
            return None
        length = struct.unpack('<I', length)[0]
        checksum = recvall(sock, 4)
        if not checksum:
            return None
        payload = recvall(sock, length)
        if not payload:
            return None
        print(
            f"Received message: magic={magic.hex()}, command={command.strip().decode()}, length={length}, checksum={checksum.hex()}, payload={payload.hex()}")
        return parse_message(magic + command + struct.pack('<I', length) + checksum + payload)
    except Exception as e:
        print(f"Error receiving message: {e}")
        return None


def request_block(sock, block_hash):
    inv_vector = struct.pack('<I', 2) + bytes.fromhex(block_hash)
    getdata_payload = struct.pack('<B', 1) + inv_vector
    send_message(sock, 'getdata', getdata_payload)


def listen_for_inv(sock):
    try:
        while True:
            message = receive_message(sock)
            if not message:
                continue
            if message.get('command') == 'inv':
                count, payload = decode_varint(message['payload'])
                for i in range(count):
                    inv_type = struct.unpack('<I', payload[:4])[0]
                    block_hash = payload[4:36].hex()
                    if inv_type == 2:  # Indicates a block
                        print(f"Requesting block with hash: {block_hash}")
                        request_block(sock, block_hash)
            elif message.get('command') == 'block':
                block = parse_block(message['payload'])
                print(f"Received block at {block['timestamp']}")
                print(f"Nonce: {block['nonce']}, Difficulty: {block['bits']}")
                for tx in block['transactions']:
                    print(f"Transaction: {tx}")
    except Exception as e:
        print(f"Error in listen_for_inv: {e}")
        sock.close()


def main():
    while True:
        node_ip = get_node_ip()
        print(f"Connecting to Bitcoin node at {node_ip}...")
        sock = connect_to_node(node_ip)
        if sock:
            print("Connected to node. Listening for blocks...")
            listen_for_inv(sock)
        else:
            print("Failed to connect to node. Retrying in 10 seconds...")
            time.sleep(10)


if __name__ == "__main__":
    main()
