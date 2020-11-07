import socket
import threading
import hashlib
import re

# loopback only
# predefined port
# predefined max connections
HOST = '127.0.0.1'
PORT = 4252
MAX_CONNECTIONS = 5


class User:
    nick = ""
    conn = None
    addr = ""

    def __init__(self, conn, addr, nick):
        self.nick = nick
        self.conn = conn
        self.addr = addr


# not for implementation yet
# this function generates a config file for clients to read on launch
# Description: Generates a configuration file for clients/servers to read from and use to manage connections
# Prerequisites: Server Nickname, port number, maximum connections to use, password(optional)
# Postrequisites: Returns nothing, generates .echat config file in the same directory as the server script
def cfg_file_generator():
    print("Server Nickname:")
    sname = input()
    formattedSname = re.sub(r'\W+', '', sname)
    with open(formattedSname + ".echat", "w") as target:
        target.write("[server]" + "\n")
        target.write("serverNickname=" + sname + "\n")
        print("Target port number:")
        pnum = input()
        target.write("targetPort=" + pnum + "\n")
        print("Maximum active connections:")
        mcon = input()
        target.write("maxConnections=" + mcon + "\n")
        print("Password [optional]:")
        passwd = input()
        if passwd:
            # WARNING: This is NOT a secure way to store a password! This is an unsalted hash, and it is relatively
            # easy to crack insecure passwords, given the hash. Be careful!
            hashp = hashlib.sha256(passwd.encode()).hexdigest()
            target.write("password=" + hashp + "\n")
        else:
            target.write("password=\"\"" + "\n")
    pass


def client_mgr(cli):
    while True:
        try:
            message = cli.conn.recv(1024)
        except ConnectionResetError:
            # Connection failed, possibly due to a non-expected termination on client side
            # i.e. client crashed or force closed
            active_connections.remove(conn)
            cli.conn.shutdown(socket.SHUT_RDWR)
            cli.conn.close()
            break
        if message:
            # handle client message here
            message = message.decode()
            print(cli.addr, ":", message)
            if message[0] == "/":
                print("Control message: ", message)
                # if control message, perform function on the server
                if not control_msg_handler(cli, message):
                    # control_msg_handler returns False, terminating connection
                    break
            # if non-control message, broadcast message
            else:
                msg_handler(cli, message)
        else:
            # message is empty. Do we kill the connection, or do we send an error message?
            # prevent empty message sent from client side?
            # remove client from the list of connected clients
            pass


def control_msg_handler(sender, message):
    # message is special command or emulates special command. "/" is first char
    # i.e. /nickname, /msg (private message), /exit or /quit, etc.
    if message == "/quit":
        print(sender.nick, " disconnecting")
        if conn in active_connections:
            active_connections.remove(sender)
        sender.conn.shutdown(socket.SHUT_RDWR)
        sender.conn.close()
        return False
    msg = message.split()
    if msg[0] == "/nick":
        if msg[1]:
            sender.nick = msg[1]
            sysnotify = "SYSTEM:Nickname updated to " + sender.nick
        else:
            sysnotify = "SYSTEM:Expected usage: /nick [new name]"
        sender.conn.send(sysnotify.encode())

    return True


def msg_handler(sender, message):
    # message is not control message
    for t in active_connections:
        # sends message to all users, including sender
        try:
            formattedMsg = sender.nick + ":" + message
            t.conn.send(formattedMsg.encode())
        except ConnectionAbortedError:
            # client no longer exists, remove from valid sender list
            active_connections.remove(t)
            t.conn.shutdown(socket.SHUT_RDWR)
            t.conn.close()
    pass


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(MAX_CONNECTIONS)
    active_connections = []
    while True:
        conn, addr = s.accept()
        newActiveUser = User(conn, addr, str(addr))
        newThread = threading.Thread(target=client_mgr, args=(newActiveUser,), name=addr)
        active_connections.append(newActiveUser)
        newThread.start()
