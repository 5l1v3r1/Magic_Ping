import struct
import socket
import time
import select
import settings

HEADER_FMT = '!BBHHH'
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_CODE = 0

timer = time.time


# TODO не отправляются/принимаются большие файлы
def get_checksum(source):
    """
    Подсчет контрольной суммы по алгоритму RFC1071
    :param source: пакет, контрольную сумму которого нужно посчитать
    :return: контрольная сумма
    """

    check_sum = 0
    count = 0

    # Считаем complement sum длиной 32 бита
    while count < len(source) - 1:
        one_step = source[count + 1] * 256 + source[count]
        check_sum += one_step
        check_sum &= 0xFFFFFFFF
        count += 2

    if len(source) % 2:
        check_sum += source[len(source) - 1]
        check_sum &= 0xFFFFFFFF

    # Сворачиваем сумму в 16 бит путём сложения её половин
    # check_sum >> 16 - получаем  "левую половину"
    # check_sum & 0xFFFF - получаем "правую половину"
    check_sum = (check_sum >> 16) + (check_sum & 0xFFFF)

    # Инвертируем
    check_sum = ~check_sum & 0xFFFF

    # Меняем местами половины контрольной суммы
    check_sum = (check_sum >> 8 & 0x00FF) | (check_sum << 8 & 0xFF00)
    socket.htons(check_sum)

    return check_sum


def reply(sock, destination_address, id, packet_number):
    sequence = packet_number % settings.MAX_SEQUENCE
    destination_address = socket.gethostbyname(destination_address)
    checksum = 0

    header = struct.pack(HEADER_FMT, ICMP_ECHO_REPLY, ICMP_CODE, checksum, id, sequence)
    data = struct.pack('iii', ICMP_ECHO_REPLY, packet_number, 0)
    packet = header + data
    data += (settings.PACKET_SIZE - len(packet))*'Q'.encode()
    packet = header + data
    checksum = get_checksum(packet)

    header = struct.pack(HEADER_FMT, ICMP_ECHO_REPLY, ICMP_CODE, checksum, id, sequence)
    packet = header + data

    sock.sendto(packet, (destination_address, settings.PORT))


def wait_reply(sock, id, packet_number):
    while True:
        select_timeout = select.select([sock], [], [], settings.TIMEOUT)

        if not select_timeout[0]:
            print("Wait reply timeout")
            return

        packet, address = sock.recvfrom(settings.PACKET_SIZE)

        header = packet[20:28]
        sock_type, code, checksum, packet_id, sequence = struct.unpack(HEADER_FMT, header)
        (sock_type,), data = struct.unpack('i', packet[28:28+struct.calcsize('i')]), packet[28+struct.calcsize('i'):]
        if sock_type == ICMP_ECHO_REPLY and id == packet_id:
            (received_packet,) = struct.unpack('i', data[:struct.calcsize('i')])

            if packet_number == received_packet:
                return True

            return


def unpack_data(fmt, data):
    size = struct.calcsize(fmt)
    (unpacking,), data = struct.unpack(fmt, data[:size]), data[size:]
    return data[:unpacking], data[unpacking:]


# TODO возвращаемое значение
def send_ping(sock, destination_address, id, data, packet_number):
    """
    Пингуем по адресу, отправляем данные
    :param sock: сокет клиента
    :param destination_address: адрес, куда отправлять данные
    :param id: в header ICMP пакета
    :param data: отправляемые данные
    :param packet_number: номер пакета
    :return:
    """
    destination_address = socket.gethostbyname(destination_address)
    checksum = 0
    sequence = packet_number % settings.MAX_SEQUENCE

    # Header: type (8), code (8), checksum (16), id (16), sequence (16)     = 64 бита = 8 байт
    # сначала делаем header с нулевой чексуммой
    data = struct.pack('iii', ICMP_ECHO_REQUEST, packet_number, len(data)) + data
    header = struct.pack(HEADER_FMT, ICMP_ECHO_REQUEST, ICMP_CODE, checksum, id, sequence)
    packet = header + data
    data += (settings.PACKET_SIZE - len(packet))*'Q'.encode()
    packet = header + data
    checksum = get_checksum(packet)
    header = struct.pack(HEADER_FMT, ICMP_ECHO_REQUEST, ICMP_CODE, checksum, id, sequence)
    packet = header + data

    flag = True
    while flag:
        sock.sendto(packet, (destination_address, settings.PORT))
        if wait_reply(sock, id, packet_number):
            flag = False


def receive_ping(sock, id, timeout=settings.TIMEOUT):
    while True:
        select_timeout = select.select([sock], [], [], timeout)

        if not select_timeout[0]:
            print("Receive timeout")
            return None, None, None

        packet, address = sock.recvfrom(settings.PACKET_SIZE)
        header = packet[20:28]
        sock_type, code, checksum, packet_id, sequence = struct.unpack(HEADER_FMT, header)
        (sock_type,), data = struct.unpack('i', packet[28:28+struct.calcsize('i')]), packet[28+struct.calcsize('i'):]

        if packet_id == id and sock_type == ICMP_ECHO_REQUEST:
            info_size = struct.calcsize('ii')
            (packet_number, len_data), data = struct.unpack('ii', data[:info_size]), data[info_size:]
            data = data[:len_data]
            reply(sock, address[0], id, packet_number)
            return address, packet_number, data
