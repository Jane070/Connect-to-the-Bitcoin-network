
import time
from node_communication import get_node_ip, connect_to_node, listen_for_inv



# Main function to establish connection to a Bitcoin node and listen for blocks
def main():
    while True:
        node_ip = get_node_ip()

        # node_ip = '185.197.160.61'

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

