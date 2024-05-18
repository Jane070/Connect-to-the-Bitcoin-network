import struct
from utils import decode_varint, format_timestamp


# Function to parse a variable integer from a byte stream
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


# Function to parse a transaction output from a byte stream
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


# Function to parse a transaction from a byte stream
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

# Function to display details of a transaction
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
        value_btc = tx_output['value'] / 1e8  # Convert to Bitcoin
        total_output_value += value_btc
        print(f"  Value: {value_btc} BTC")
        print(f"  Script PubKey: {tx_output['script_pubkey']}")
    print(f"Total Output Value: {total_output_value} BTC")
    print(f"Locktime: {transaction['locktime']}")


# Function to parse a block from a byte stream
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
    
    # Parsing transactions within the block
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


# Function to display details of a block
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