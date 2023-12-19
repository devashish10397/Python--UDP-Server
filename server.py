import socket
import time
import getopt
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import sys
from Packet import Packet
import threading

# Define global dictionaries for keys and binaries
keys = {}
binaries = {}

def get_expected_signature(private_key_path, packet_data):
    try:
        private_key = load_private_key(private_key_path)
        key = RSA.import_key(private_key)
        signer = pkcs1_15.new(key)
        expected_signature = signer.sign(packet_data)
        return expected_signature
    except Exception as e:
        print("You provided an invalid key or Exception:", e)
        return None

def load_private_key(private_key_path):
    # Implement your private key loading logic here
    # Return the loaded private key
    pass

def handle_packet(data):
    # Create a Packet instance from received data
    pkt = Packet(data)
    
    # Verify integrity
    if not pkt.verify_structural_integrity():
        print("*****Incorrect structure*****")

    pkt_hex_string = pkt.uniquePacketID.hex()
    # Format it with "0x"
    formatted_hex_string = "0x" + pkt_hex_string.lstrip("0")

    # Verify Signature
    if not pkt.verify_signature(keys.get(formatted_hex_string)):
        print('*****unverified signature for packet id:', formatted_hex_string)
        unverified += 1
    # Verify checksum
    if not pkt.verify_checksum():
        print('checksum for packet id:', formatted_hex_string)
        failed_checksum += 1

def packet_handler_thread(sock):
    while True:
        # Using a reasonable buffer size 1024 bytes
        data, addr = sock.recvfrom(1024)
        # Start a new thread to handle each incoming packet
        threading.Thread(target=handle_packet, args=(data,)).start()

def main(argv):
    port = 1337
    delay = 0.001  # Default delay value

    try:
        opts, _ = getopt.getopt(argv, "p:d:k:b:", ["port=", "delay=", "keys=", "binaries="])
    except getopt.GetoptError:
        print("Usage: server.py -p <port> -d <delay> -k <keys> -b <binaries>")
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-p", "--port"):
            port = int(arg)
        elif opt in ("-d", "--delay"):
            delay = float(arg)
        elif opt in ("-k", "--keys"):
            keys = json.loads(arg)  # Parse JSON input and store in the 'keys' dictionary
        elif opt in ("-b", "--binaries"):
            binaries = json.loads(arg)  # Parse JSON input and store in the 'binaries' dictionary

    host = '127.0.0.1'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    # Introduce a delay if there is no delay (delay == 0)
    if delay == 0:
        delay = 0.001

    count = 0
    unverified = 0
    failed_checksum = 0

    # Start the packet handling thread
    threading.Thread(target=packet_handler_thread, args=(sock,)).start()

if __name__ == "__main__":
    main(sys.argv[1:])
