import socket
import magic_ping
import os
import settings

print("START SERVER!!!")

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.bind(('', settings.PORT))

clients = {}

file = None
ID = 1
count = 0
while True:
    client_address, packet_number, data = magic_ping.receive_ping(s, ID)

    if not client_address:
        continue
    if packet_number == 1:
        file_name, data = magic_ping.unpack_data('i', data)
        file_name = 'test_files/received_' + file_name.decode()
        clients[client_address[0]] = file_name
        file = open(file_name, 'wb')
        os.chmod(file_name, 0o666)
        continue

    if file and packet_number > 1:
        count += 1
        print(count)
        file.write(data)
        continue

    if file and packet_number == 0:
        count += 1
        file.close()
        break

s.close()
print("receive:", count)
