import socket
import time
import hashlib
import struct
from datetime import datetime
from utils import create_version_payload, parse_message, verify_block_hash, decode_varint, format_timestamp


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

def send_pong(sock, nonce):
    print("Sending pong message...")
    send_message(sock, 'pong', nonce)
    print("Sent pong message in response to ping")

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
    


def request_data(sock, inv_type, inv_hash):
    inv_vector = struct.pack('<I', inv_type) + bytes.fromhex(inv_hash)
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

def parse_varint(data, offset):
    n = data[offset]
    offset += 1
    if n < 0xfd:
        return n, offset
    elif n == 0xfd:
        return struct.unpack('<H', data[offset:offset + 2])[0], offset + 2
    elif n == 0xfe:
        return struct.unpack('<I', data[offset:offset + 4])[0], offset + 4
    else:
        return struct.unpack('<Q', data[offset:offset + 8])[0], offset + 8

def parse_output(data, offset):
    value = struct.unpack('<Q', data[offset:offset + 8])[0]
    offset += 8
    script_length, offset = parse_varint(data, offset)
    script_pubkey = data[offset:offset + script_length].hex()
    offset += script_length
    return {
        'value': value,
        'script_pubkey': script_pubkey
    }, offset

def parse_transaction(payload):
    offset = 0
    version = struct.unpack('<I', payload[offset:offset + 4])[0]
    offset += 4
    input_count, offset = parse_varint(payload, offset)
    inputs = []
    for _ in range(input_count):
        prev_tx_hash = payload[offset:offset + 32][::-1].hex()
        offset += 32
        prev_tx_index = struct.unpack('<I', payload[offset:offset + 4])[0]
        offset += 4
        script_length, offset = parse_varint(payload, offset)
        script_sig = payload[offset:offset + script_length].hex()
        offset += script_length
        sequence = struct.unpack('<I', payload[offset:offset + 4])[0]
        offset += 4
        inputs.append({
            'prev_tx_hash': prev_tx_hash,
            'prev_tx_index': prev_tx_index,
            'script_sig': script_sig,
            'sequence': sequence
        })
    output_count, offset = parse_varint(payload, offset)
    outputs = []
    for _ in range(output_count):
        tx_output, offset = parse_output(payload, offset)
        outputs.append(tx_output)
    locktime = struct.unpack('<I', payload[offset:offset + 4])[0]
    return {
        'version': version,
        'inputs': inputs,
        'outputs': outputs,
        'locktime': locktime
    }

def display_transaction_details(transaction):
    print(f"Transaction Version: {transaction['version']}")
    print("Inputs:")
    for tx_input in transaction['inputs']:
        print(f"  Previous Transaction Hash: {tx_input['prev_tx_hash']}")
        print(f"  Previous Transaction Index: {tx_input['prev_tx_index']}")
        print(f"  Script Signature: {tx_input['script_sig']}")
        print(f"  Sequence: {tx_input['sequence']}")
    print("Outputs:")
    total_output_value = 0
    for tx_output in transaction['outputs']:
        value_btc = tx_output['value'] / 1e8  # 转换为比特币单位
        total_output_value += value_btc
        print(f"  Value: {value_btc} BTC")
        print(f"  Script PubKey: {tx_output['script_pubkey']}")
    print(f"Total Output Value: {total_output_value} BTC")
    print(f"Locktime: {transaction['locktime']}")

def parse_block(payload):
    offset = 0
    version = struct.unpack('<I', payload[offset:offset + 4])[0]
    offset += 4
    prev_block = payload[offset:offset + 32][::-1].hex()
    offset += 32
    merkle_root = payload[offset:offset + 32][::-1].hex()
    offset += 32
    timestamp = struct.unpack('<I', payload[offset:offset + 4])[0]
    offset += 4
    bits = struct.unpack('<I', payload[offset:offset + 4])[0]
    offset += 4
    nonce = struct.unpack('<I', payload[offset:offset + 4])[0]
    offset += 4
    
    transaction_count, offset = parse_varint(payload, offset)
    transactions = []
    for _ in range(transaction_count):
        tx_length, new_offset = parse_varint(payload, offset)
        transaction = payload[offset:new_offset + tx_length]
        transactions.append(parse_transaction(transaction))
        offset = new_offset + tx_length
    
    return {
        'version': version,
        'prev_block': prev_block,
        'merkle_root': merkle_root,
        'timestamp': timestamp,
        'bits': bits,
        'nonce': nonce,
        'transactions': transactions
    }



def display_block_details(block):
    print(f"Block Version: {block['version']}")
    print(f"Previous Block Hash: {block['prev_block']}")
    print(f"Merkle Root: {block['merkle_root']}")
    print(f"Timestamp: {format_timestamp(block['timestamp'])}")
    print(f"Bits: {block['bits']}")
    print(f"Nonce: {block['nonce']}")
    print("Transactions:")
    for transaction in block['transactions']:
        display_transaction_details(transaction)


def main():
    while True:
        node_ip = get_node_ip()

        # node_ip = '101.182.89.82'

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

