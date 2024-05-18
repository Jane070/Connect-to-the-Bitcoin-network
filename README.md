# Connect-to-the-Bitcoin-network

## Overview

Bitcoin Node Connector is a Python application that facilitates communication with a Bitcoin node and allows for the retrieval and parsing of block data. It enables users to connect to a Bitcoin node, send and receive messages, parse transaction and block data.

## Repository

The source code for this project is hosted on [GitHub](https://github.com/Jane070/Connect-to-the-Bitcoin-network.git).

## Dependencies

To build and run this application, you will need:

- Python 3.x


## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Jane070/Connect-to-the-Bitcoin-network.git



## Usage

1. Ensure that a Bitcoin node is running and accessible.

2. Run the application using the following command:

    ```bash
    python3 main.py

3. The application will establish a connection to the Bitcoin node, initiate a handshake, and start listening for events.

4. Upon receiving blocks or tx from the node, the application will parse and display details.

## Architecture Overview

The codebase is organized into the following modules:

'main.py': Main entry point of the application.

'node_communication.py': Handles all communication with the Bitcoin node (connecting, sending, and receiving messages).

'parsing.py': Contains all parsing-related functions.

'utils.py': Contains utility functions for creating version payloads, parsing messages, and verifying block hashes.

## Output Example

Received message:  
- **Magic:** f9beb4d9  
- **Command:** tx  
- **Length:** 189  
- **Checksum:** e85b3239  
- **Payload:** 010000000145f0dd42936b7cc94449de45cf175a362ecfe13b1f21bdba57cfc5f792573831000000006b483045022100d1b353fbcbc5dcd6824fa202f47b61b47639acdc8575c6310aed0914776013f402200c5ef28b959cc09d1f2a8f32d1087f6819bb2ba9b778ad66acf077d926896c64012103127a9db3ba7f33a9848dcdc95a9422a09b2dcd49a2e0c015a657f136f5389e3dfdffffff01046a050000000000160014fbede933a0d8c0410a29cf1ba7155c7316ff2d0d00000000
- **Transaction Version:** 1

**Inputs:**  
- **Previous Transaction Hash:** 31385792f7c5cf57babd211f3be1cf2e365a17cf45de4944c97c6b9342ddf045  
- **Previous Transaction Index:** 0  
- **Script Signature:**  483045022100d1b353fbcbc5dcd6824fa202f47b61b47639acdc8575c6310aed0914776013f402200c5ef28b959cc09d1f2a8f32d1087f6819bb2ba9b778ad66acf077d926896c64012103127a9db3ba7f33a9848dcdc95a9422a09b2dcd49a2e0c015a657f136f5389e3d

- **Sequence:** 4294967293

**Outputs:**  
- **Value:** 0.0035482 BTC  
- **Script PubKey:** 0014fbede933a0d8c0410a29cf1ba7155c7316ff2d0d

**Total Output Value:** 0.0035482 BTC



## Troubleshooting

If you encounter any issues while running the application, consider the following troubleshooting steps:

- Check your internet connection and ensure that the Bitcoin node is accessible.
- If the application freezes or fails to connect, try running it again. Occasionally, network issues or server timeouts may cause the program to freeze temporarily.
- If the application successfully connects but does not receive events, try running it again. Bitcoin nodes may occasionally experience delays or be busy processing other requests. Re-running the application can sometimes resolve this issue.


