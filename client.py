import socket
import threading
import select

HOST = '127.0.0.1'
PORT = 4252


def send_handler(s):
    while True:
        s.send(input().encode())


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    sender = threading.Thread(target=send_handler,args=(s,))
    sender.start()
    while True:
        r, _, _ = select.select([s], [], [])
        for rs in r:
            if s == rs:
                data = rs.recv(1024)
                print(data.decode())
