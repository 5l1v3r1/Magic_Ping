import struct

PORT = 9090
PACKET_SIZE = 192
DATA_SIZE = PACKET_SIZE-28-struct.calcsize('iii')
TIMEOUT = 5
MAX_SEQUENCE = 2**16-1
