import struct
import hashlib


def md5_checksum(file_path):
    with open(file_path, 'rb') as fh:
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()

# Это лучше не трогать!
PACKET_SIZE = 65000
DATA_SIZE = PACKET_SIZE-28-struct.calcsize('iii')
MAX_SEQUENCE = 2**16-1
KEY = [i for i in range(0, DATA_SIZE)]

# Это трогать можно
PORT = 9090
TIMEOUT = 5
