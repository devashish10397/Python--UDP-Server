import pickle
import socket
import time
import random

random.seed(0x1337)

with open('payload_dump.bin', 'rb') as f:
    payloads = pickle.load(f, encoding="bytes")

# socket for sending
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
count = 0
# debug
# print('sending')
for payload in payloads:
    print('count: ', count)
    print(payload)
    #print(type(payload))
    count += 1
    sock.sendto(payload, ('127.0.0.1', 1337))
    time.sleep(0.001)
    # break

sock.close()
