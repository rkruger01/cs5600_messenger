import socket

HOST = '127.0.0.1'
PORT = 4252

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(5)
    conn, addr = s.accept()
    with conn:
        print("Connected to", addr)
        while True:
            data = conn.recv(1024)
            if not data:
                print(addr, " Terminated")
                break
            msg = data.decode()
            newMsg = addr[0] + ":" + msg
            conn.sendall(newMsg.encode())
