import socket
import struct
import hashlib
from utils import create_version_payload, parse_message, decode_varint, format_timestamp, send_message, send_pong
from parsing import parse_transaction, parse_block, display_transaction_details, display_block_details

# Function to get the IP address of a Bitcoin node using a domain name
def get_node_ip(domain='seed.bitcoin.sipa.be'):
    return socket.gethostbyname_ex(domain)[2][0]

# Function to establish a connection to a Bitcoin node
def connect_to_node(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, 8333))  # Bitcoin default port is 8333

        version_payload = create_version_payload()
        print(f"Sending version message: {version_payload.hex()}")

        send_message(sock, 'version', version_payload)

        # Receiving and verifying the version message from the node
        response = receive_message(sock)  # Expecting version message

        if response and response.get('command') == 'version':
            print(f"Received version message: {response}")

             # Sending a verack message to acknowledge the version message
            send_message(sock, 'verack', b'')
            print("Sent verack message")
            return sock
        else:
            print(f"Expected version message but received: {response}")
        
        sock.close()
        print("Failed to complete handshake with node.")
        return None
    
    except Exception as e:
        print(f"Error connecting to node: {e}")
        return None
    

# Function to receive a message from the Bitcoin node
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
        
        command_str = command.strip(b'\x00').decode()
        print(
            f"Received message: magic={magic.hex()}, command={command_str}, length={length}, checksum={checksum.hex()}, payload={payload.hex()}")
         # Check for ping and respond with pong
        if command_str == 'ping':
            print("Received ping message.")
            send_pong(sock, payload)  # Send pong with the same nonce received in ping
            return None
        return parse_message(magic + command + struct.pack('<I', length) + checksum + payload)
    except Exception as e:
        print(f"Error receiving message: {e}")
        return None


# Function to request data (transactions or blocks) from the Bitcoin node
def request_data(sock, inv_type, inv_hash):
    inv_vector = struct.pack('<I', inv_type) + bytes.fromhex(inv_hash)
    getdata_payload = struct.pack('<B', 1) + inv_vector
    send_message(sock, 'getdata', getdata_payload)



# Function to listen for inventory (inv) messages from the Bitcoin node
def listen_for_inv(sock):
    try:
        while True:
            message = receive_message(sock)
            if not message:
                continue
            if message.get('command') == 'inv':
                count, payload = decode_varint(message['payload'])
                offset = 0
                for _ in range(count):
                    inv_type = struct.unpack('<I', payload[offset:offset+4])[0]
                    inv_hash = payload[offset+4:offset+36].hex()
                    offset += 36
                    if inv_type == 1:  # Indicates a transaction
                        print(f"Requesting transaction with hash: {inv_hash}")
                        request_data(sock, inv_type, inv_hash)
                    elif inv_type == 2:  # Indicates a block
                        print(f"Requesting block with hash: {inv_hash}")
                        request_data(sock, inv_type, inv_hash)
            elif message.get('command') == 'tx':
                transaction = parse_transaction(message['payload'])
                display_transaction_details(transaction)
            elif message.get('command') == 'block':
                block = parse_block(message['payload'])
                display_block_details(block)
    except Exception as e:
        print(f"Error in listen_for_inv: {e}")
        sock.close()
