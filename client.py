import socket
import argparse
import sys
import magic_ping
import os
import settings
import signal
import logging
import struct

logging.basicConfig(format=u'%(levelname)-8s [%(asctime)s] %(message)s', level=logging.DEBUG, filename=u'client.log')


# Обработка CTRL+C
def signal_handler(signal, frame):
    print("\nSTOP CLIENT.")
    logging.info("STOP CLIENT.")
    exit(0)


# Парсер аргументов командной строки
def create_cmd_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, type=argparse.FileType(mode='rb'))
    parser.add_argument('-a', '--address', required=True)
    parser.add_argument('-c', '--cypher', action='store_const', const=True)

    return parser

signal.signal(signal.SIGINT, signal_handler)

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
    data = file_name.encode()
    if arguments.cypher:
        data = struct.pack('b', 1) + data
    else:
        data = struct.pack('b', 0) + data
    logging.debug("Start sending file to %s" % address)
    magic_ping.send_ping(s, address, ID, data, packet_number)

    print('start sending')

    already_sent = 0  # размер уже отправленной части

    while True:
        data = file.read(settings.DATA_SIZE)
        if arguments.cypher:
            data = [a ^ b for (a, b) in zip(data, settings.KEY)]  # шифруем XORом с ключом
            data = bytes(data)
        if not data:
            break

        already_sent += len(data)
        packet_number += 1
        magic_ping.send_ping(s, address, ID, data, packet_number)
        logging.info('Отправлено: %.2f %%' % (already_sent / file_size * 100))
        print('Отправлено: %.2f %%' % (already_sent / file_size * 100))

    magic_ping.send_ping(s, address, ID, bytes(0), packet_number=0)
    logging.debug("Packets sent: %d" % packet_number)
    print("send:", packet_number)
    file.close()

    client_address, packet_number, checksum = magic_ping.receive_ping(s, ID, {})  # проверяем корректность передачи
    if checksum and settings.md5_checksum(file_name) != checksum.decode():
        logging.warning("Файл передался с ошибками!!!")
        print("Файл передался с ошибками!!!")
    s.close()
