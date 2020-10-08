import socket
import threading

# loopback only
# predefined port
# predefined max connections
HOST = '127.0.0.1'
PORT = 4252
MAX_CONNECTIONS = 5


def client_mgr(conn, addr):
    while True:
        message = conn.recv(2048)
        if message:
            # handle client message here
            # if control message, perform function on the server
            control_msg_handler(conn, addr, message)
            # if non-control message, broadcast message
            msg_handler(conn, addr, message)
        else:
            # message is empty. Do we kill the connection, or do we send an error message?
            # prevent empty message sent from client side?
            # remove client from the list of connected clients
            pass


def control_msg_handler(conn, addr, message):
    # message is special command
    # i.e. /nickname, /msg (private message), /exit or /quit, etc.
    pass


def msg_handler(conn, addr, message):
    # message is not control message
    for t in active_connections:
        if t is not conn:
            # found non-self target for message
            t.send(message)
    pass


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(MAX_CONNECTIONS)
    active_connections = []
    while True:
        conn, addr = s.accept()
        newThread = threading.Thread(target=client_mgr, args=(conn, addr), name=addr)
        active_connections.append(conn)
        newThread.start()
