import struct

# Это лучше не трогать!
PACKET_SIZE = 192
DATA_SIZE = PACKET_SIZE-28-struct.calcsize('iii')
MAX_SEQUENCE = 2**16-1
KEY = [i for i in range(0, DATA_SIZE)]

# Это трогать можно
PORT = 9090
TIMEOUT = 5
