import hashlib
import pickle
import re
import socket
import threading
from random import choice
from string import hexdigits, ascii_letters

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.PublicKey import RSA

# Dictionary of alert messages
# Allows for unified updates across codebase, easier localization
serverAlertMessages = {
    "NICKUPDATE": "Nickname updated to ",
    "NICKBADARGS": "Expected usage: /nick [new name]",
    "COLORUPDATE": "Color updated to ",
    "COLORBADARGS": "Expected usage: /color hexcolor",
    "RSAKEYEXCHANGEERROR": "Critical error: RSA key exchange was unsuccessful",
}

# loopback only
# predefined port
# predefined max connections
HOST = '127.0.0.1'
PORT = 4252
MAX_CONNECTIONS = 5


class User:
    nick = None
    conn = None
    addr = None
    color = None
    RSAPublicKey = None
    clientEncryptor = None

    def __init__(self, conn, addr, nick, publicKey, color="#000000"):
        self.color = color
        self.nick = nick
        self.conn = conn
        self.addr = addr
        self.RSAPublicKey = publicKey
        self.clientEncryptor = PKCS1_OAEP.new(publicKey)


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
            # easy to crack insecure passwords, given the hash. For more secure applications, consider salting the
            # hashes, or not including the password (or the hash) in plaintext at all.
            hashp = hashlib.sha256(passwd.encode()).hexdigest()
            target.write("password=" + hashp + "\n")
        else:
            target.write("password=\"\"" + "\n")
    pass


# This handles each client connected to the server. If a client termimates their connection irregularly, i.e. force
# closes the connection instead of notifying the server and gracefully closing, those errors are caught in here and
# handled. Afterwards, the thread self-terminates.
def client_mgr(cli, serverEncryptor: PKCS1OAEP_Cipher):
    while True:
        try:
            message = cli.conn.recv(4096)
        except ConnectionResetError:
            # Connection failed, possibly due to a non-expected termination on client side
            # i.e. client crashed or force close
            try:
                active_connections.remove(conn)
                cli.conn.shutdown(socket.SHUT_RDWR)
                cli.conn.close()
            except ValueError:
                pass
            break
        if message:
            # handle client message here
            # decrypt message object
            message = serverEncryptor.decrypt(message)
            message = pickle.loads(message)
            print(cli.addr, ":", message[1])
            if message[0]:
                # if message[0] is true for messages sent to the server, that message is a control message
                # think /quit, /nick, etc.
                if not control_msg_handler(cli, message[1]):
                    # control_msg_handler returns False, so we are terminating connection
                    break
            # if non-control message, broadcast message
            else:
                msg_handler(cli, message[1])
        else:
            # message is empty. Do we kill the connection, or do we send an error message?
            # prevent empty message sent from client side?
            # remove client from the list of connected clients
            pass


# Expects: sender to be an instance of class User, message to be a String or similar
# Handles any control messages sent to the server, for example, nickname changes, color changes, quitting
# Returns True if client remains connected, False if client has terminated their connection.
def control_msg_handler(sender, message):
    if message == "/quit":
        print(sender.nick, " disconnecting")
        if conn in active_connections:
            active_connections.remove(sender)
        sender.conn.shutdown(socket.SHUT_RDWR)
        sender.conn.close()
        return False
    # splits message apart to handle command arguments
    msg = message.split()
    if msg[0] == "/nick":
        # User wants to change nickname\
        try:
            # TODO: Validate name (no admin strings, no special characters, no repeats)
            sender.nick = msg[1]
            sysmsg = serverAlertMessages["NICKUPDATE"] + sender.nick
        except IndexError:
            sysmsg = serverAlertMessages["NICKBADARGS"]
        msg = pickle.dumps([True, "#FFFFFF", "SYSTEM", sysmsg])
        msg = sender.clientEncryptor.encrypt(msg)
        sender.conn.send(msg)
    # user wants to change their associated message color:
    if msg[0] == "/color":
        try:
            if msg[1].startswith("#"):
                hexcode = msg[1][1:]
            else:
                hexcode = msg[1]
            if all(c in hexdigits for c in hexcode) and len(hexcode) == 6:
                sender.color = "#" + hexcode
                sysmsg = serverAlertMessages["COLORUPDATE"] + sender.color
            else:
                sysmsg = serverAlertMessages["COLORBADARGS"]
        except IndexError:
            sysmsg = serverAlertMessages["COLORBADARGS"]
        msg = pickle.dumps([True, "#FFFFFF", "SYSTEM", sysmsg])
        msg = sender.clientEncryptor.encrypt(msg)
        sender.conn.send(msg)
    return True


# Expects: sender to be an instance of class User, message to be a String or similar
# Function sends message to all connected clients, user included.
# If a connection no longer exists, msg_handler automatically removes it from the active connection list.
# Returns: None
def msg_handler(sender, message):
    # message is not control message
    for t in active_connections:
        # sends message to all users, including sender
        try:
            formattedMsg = [False, sender.color, sender.nick, message]
            formattedMsg = pickle.dumps(formattedMsg)
            formattedMsg = t.clientEncryptor.encrypt(formattedMsg)
            t.conn.send(formattedMsg)
        except ConnectionAbortedError:
            # client no longer exists, remove from valid sender list
            active_connections.remove(t)
            t.conn.shutdown(socket.SHUT_RDWR)
            t.conn.close()
    pass


def keyExchange(conn, serverKey, serverEncryptor):
    conn.sendall(serverKey.publickey().export_key('DER'))
    clientPublicKey = RSA.importKey(conn.recv(4096))
    # generates a random ascii string to verify key handshake successful
    clientEncryptor = PKCS1_OAEP.new(clientPublicKey)
    msg = ''.join(choice(ascii_letters) for i in range(20)).encode()
    encMsg = clientEncryptor.encrypt(msg)
    conn.sendall(encMsg)
    # Client has encrypted message. Now, wait for client to decrypt with private key, and encrypt again with
    # server public key. Receive message and decode.
    clientEncryptedMessage = conn.recv(4096)
    clientDecryptedMessage = serverEncryptor.decrypt(clientEncryptedMessage)
    # Compare bitstrings here. If encryption was successful, they should be equal.
    goodKeyExchange = (msg == clientDecryptedMessage)
    return clientPublicKey, goodKeyExchange


# Main
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    serverKey = RSA.generate(2048)
    serverEncryptor = PKCS1_OAEP.new(serverKey)
    # serverKey contains both private and public key
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(MAX_CONNECTIONS)
    active_connections = []
    while True:
        conn, addr = s.accept()
        # TODO: Add password exchange here
        clientPublicKey, goodKeyExchange = keyExchange(conn, serverKey, serverEncryptor)
        if not goodKeyExchange:
            # Critical error: key exchange failed
            # Notify client, terminate connection and wait for next connection
            msg = pickle.dumps([True, "#FFFFFF", "SYSTEM", serverAlertMessages["RSAKEYEXCHANGEERROR"]])
            conn.sendall(msg)
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            continue
        newActiveUser = User(conn, addr, str(addr), clientPublicKey)
        newThread = threading.Thread(target=client_mgr, args=(newActiveUser, serverEncryptor,), name=addr)
        active_connections.append(newActiveUser)
        newThread.start()
