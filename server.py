import socket
import magic_ping
import os
import settings
import datetime
import signal
import logging
import struct

logging.basicConfig(format=u'%(levelname)-8s [%(asctime)s] %(message)s', level=logging.DEBUG, filename=u'server.log')


# Обработка CTRL+C
def signal_handler(signal, frame):
    print("\nSTOP SERVER.")
    s.close()
    logging.info("STOP SERVER.")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

print("START SERVER!!!")
logging.info("START SERVER!!!")

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.bind(('', settings.PORT))

files = {}  # словарь с парами адрес : файл. Для одновременного приема разных файлов от разных клиентов
counters = {}  # тоже самое для счетчиков пакетов
cypher = {}  # клиенты передающие зашифрованные файлы
file_names = {}  # имена файлов клиентов

file = None
ID = 1
while True:
    client_address, packet_number, data = magic_ping.receive_ping(s, ID, counters)

    if not client_address:
        continue

    if packet_number == 1:
        # кортеж с именами директорий, которые нужно создать
        path = (client_address[0], datetime.datetime.now().strftime("%d-%m-%Y %H:%M"))

        tmp = ''  # путь до самой глубокой директории, создаваться они будут по очереди
        for dir_name in path:
            if len(tmp):
                tmp += '/' + dir_name
            else:
                tmp = dir_name
            try:
                os.mkdir(tmp)
                logging.debug("Create folder: %s" % tmp)
                os.chmod(tmp, 0o777)
            except FileExistsError:  # если такая директория уже существует, то просто создаем следующую
                pass

        info, data = data[:struct.calcsize('b')], data[struct.calcsize('b'):]
        (info,) = struct.unpack('b', info)  # info - флаг, зашифрован файл или нет
        if info:
            cypher[client_address[0]] = True
        else:
            cypher[client_address[0]] = False

        file_name = data.decode().split('/')[-1]  # если имя файла было передано с учетом каталогов, избавляемся от них
        logging.debug("Receive new file: %s, from: %s" % (file_name, client_address[0]))
        file_name = tmp + '/' + file_name  # имя файла с учетом директорий, в которых он должен находиться
        file_names[client_address[0]] = file_name
        file = open(file_name, 'wb')
        os.chmod(file_name, 0o777)  # так как работаем от рута, даем доступ всем остальным

        files[client_address[0]] = file
        counters[client_address[0]] = 1
        continue

    if files.get(client_address[0]) and packet_number > 1:
        counters[client_address[0]] += 1
        logging.debug("%d packet has been received" % counters[client_address[0]])
        if cypher[client_address[0]]:
            data = [a ^ b for (a, b) in zip(data, settings.KEY)]  # дешифрование - посимвольно XORим с ключом
            data = bytes(data)
        files[client_address[0]].write(data)
        continue

    if files.get(client_address[0]) and packet_number == 0:  # последний пакет имеет нулевой номер
        files[client_address[0]].close()
        logging.info("receive file from: %s, number of packets: %d" % (client_address[0], counters[client_address[0]]))
        print("receive file from:", client_address[0], "number of packets:", counters[client_address[0]])
        # отправляем чексумму принятого файла
        magic_ping.send_ping(s, client_address[0], ID, settings.md5_checksum(file_names[client_address[0]]).encode(), 0)

        counters.pop(client_address[0])
        files.pop(client_address[0])
        cypher.pop(client_address[0])
        file_names.pop(client_address[0])

