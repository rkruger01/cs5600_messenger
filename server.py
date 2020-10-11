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
        try:
            message = conn.recv(1024)
        except ConnectionResetError:
            # Connection failed, possibly due to a non-expected termination on client side
            # i.e. client crashed or force closed
            active_connections.remove(conn)
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            break
        if message:
            # handle client message here
            message = message.decode()
            print(addr, ":", message)
            if message[0] == "/":
                print("Control message: ", message)
                # if control message, perform function on the server
                if not control_msg_handler(conn, message):
                    # control_msg_handler returns False, terminating connection
                    break
            # if non-control message, broadcast message
            msg_handler(conn, message)
        else:
            # message is empty. Do we kill the connection, or do we send an error message?
            # prevent empty message sent from client side?
            # remove client from the list of connected clients
            pass


def control_msg_handler(conn, message):
    if message == "/quit":
        print(conn, " disconnecting")
        if conn in active_connections:
            active_connections.remove(conn)
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        return False
    # message is special command
    # i.e. /nickname, /msg (private message), /exit or /quit, etc.
    pass


def msg_handler(conn, message):
    # message is not control message
    for t in active_connections:
        if t is not conn:
            # found non-self target for message
            try:
                t.send(message.encode())
            except ConnectionAbortedError:
                # client no longer exists, remove from valid sender list
                active_connections.remove(t)
                t.shutdown(socket.SHUT_RDWR)
                t.close()
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
