import struct
import socket
import argparse
import sys
import magic_ping
import os
import settings


def create_cmd_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, type=argparse.FileType(mode='rb'))
    parser.add_argument('-a', '--address', required=True)

    return parser

if __name__ == '__main__':
    p = create_cmd_parser()
    arguments = p.parse_args(sys.argv[1:])
    file = arguments.file
    file_name = file.name
    file_size = os.stat(file_name).st_size
    address = arguments.address
    ID = 1
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    packet_number = 1
    file_name = file_name.split('/')[1]
    data = struct.pack('i', len(file_name)) + file_name.encode()
    magic_ping.send_ping(s, address, ID, data, packet_number)  # TODO принимать ответ и менять айди, если 1 занят

    print('start sending')

    already_sent = 0

    while True:
        data = file.read(settings.DATA_SIZE)
        #print(data)
        if not data:
            break

        already_sent += len(data)
        packet_number += 1
        magic_ping.send_ping(s, address, ID, data, packet_number)
        print('Отправлено: %.2f %%' % (already_sent / file_size * 100))

    magic_ping.send_ping(s, address, ID, bytes(0), packet_number=0)
    print("send:", packet_number)
    print("OK!")
    file.close()
    s.close()
