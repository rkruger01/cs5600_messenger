import socket
import threading
import select

HOST = '127.0.0.1'
PORT = 4252


def send_handler(s):
    while True:
        msg = input()
        if msg == "/quit":
            s.send("/quit".encode())
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            break
        s.send(msg.encode())


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    sender = threading.Thread(target=send_handler, args=(s,))
    sender.start()
    while True:
        if s.fileno() == -1:
            # socket closed
            break
        r, _, _ = select.select([s], [], [])
        for rs in r:
            if s == rs:
                try:
                    data = rs.recv(1024)
                except OSError:
                    # connection terminated (for some reason)
                    break
                if not data:
                    break
                print(data.decode())
