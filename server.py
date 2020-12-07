import configparser
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
from requests import get

# Dictionary of alert messages
# Allows for unified updates across codebase, easier localization
serverAlertMessages = {
    "NICKUPDATE": "Nickname updated to ",
    "NICKBADARGS": "Expected usage: /nick [new name]",
    "NICKBADCHARS": "Error: Non-alphanumeric characters found. Acceptable characters are a-z, A-Z, 0-9, and underscore.",
    "NICKBADLENGTH": "Error: Usernames must be between 3 and 24 characters.",
    "NICKILLEGALNAME": "Error: That username is not allowed!",
    "NICKREPEAT": "Error: Another user already has that name!",
    "COLORUPDATE": "Color updated to ",
    "COLORBADARGS": "Expected usage: /color [hexcolor]",
    "RSAKEYEXCHANGEERROR": "Critical error: RSA key exchange was unsuccessful",
    "DIRECTMESSAGEBADARGS": "Expected usage: /msg [target user] [message]",
    "DIRECTMESSAGENOUSER": "Error: No such user: ",
    "DIRECTMESSAGESELFMESSAGE": "Error: Why would you need to direct message yourself?",
    "SERVERSHUTDOWNMANUAL": "The server is going down for maintenance NOW!",
    "USERDISCONNECT": " has disconnected",
    "USERCONNECT": " has connected",
}
# Blacklisted usernames for users
nonAllowedUsernames = ["admin", "server", "administrator"]

# predefined max connections
MAX_CONNECTIONS = 50


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


# this function generates a config file for clients to read on launch
# Description: Generates a configuration file for clients/servers to read from and use to manage connections
# Prerequisites: Server Nickname, server IP address, port number, password(optional)
# Postrequisites: Returns nothing, generates .echat config file in the same directory as the server script
def cfg_file_generator():
    # To include: server IP, port, password, server nickname
    config = configparser.ConfigParser()
    print("Server Nickname:")
    sname = input()
    # fetches external IP address for auto-configuration
    # possibly add switch here in the future?
    externalIP = get('https://api.ipify.org').text
    print("Server IP (defaults to {}):".format(externalIP))
    ip = input()
    if not ip:
        ip = externalIP
    print("Server Port:")
    port = input()
    print("Password (optional):")
    password = input()
    formattedSname = re.sub(r'\W+', '', sname)
    if password:
        # WARNING: This is not a secure way to store a password!
        hashedPassword = hashlib.sha256(password.encode()).hexdigest()
    else:
        hashedPassword = ''
    config['SERVER'] = {
        'ServerIP': str(ip),
        'ServerPORT': str(port),
        'ServerPASSWORD': str(hashedPassword),
        'ServerNICKNAME': str(sname)
    }
    with open(formattedSname + ".echat", "w") as target:
        config.write(target)


# This handles each client connected to the server. If a client termimates their connection irregularly, i.e. force
# closes the connection instead of notifying the server and gracefully closing, those errors are caught in here and
# handled. Afterwards, the thread self-terminates.
def client_mgr(cli, serverEncryptor: PKCS1OAEP_Cipher):
    while True:
        try:
            message = cli.conn.recv(4096)
        except (ConnectionResetError, ConnectionAbortedError):
            # Connection failed, possibly due to a non-expected termination on client side
            # i.e. client crashed or force close
            try:
                active_connections.remove(cli)
                cli.conn.shutdown(socket.SHUT_RDWR)
                cli.conn.close()
                msg_handler(User(None, None, "< SERVER BROADCAST >", None, "#FF0000"),
                            cli.nick + serverAlertMessages["USERDISCONNECT"])
            except ValueError:
                pass
            break
        if message:
            # handle client message here
            # decrypt message object
            message = serverEncryptor.decrypt(message)
            message = pickle.loads(message)
            print(cli.nick, ":", message[1])
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
    if message in ["/quit", "/exit"]:
        print(sender.nick, " disconnecting")
        if sender in active_connections:
            active_connections.remove(sender)
        sender.conn.shutdown(socket.SHUT_RDWR)
        sender.conn.close()
        msg_handler(User(None, None, "< SERVER BROADCAST >", None, "#FF0000"),
                    sender.nick + serverAlertMessages["USERDISCONNECT"])
        return False
    # splits message apart to handle command arguments
    msg = message.split()
    if msg[0] in ["/users", "/who"]:
        # client wants a list of connected users
        users = "Connected Users: "
        for c in active_connections:
            users = users + c.nick + ", "
        msg = pickle.dumps([True, "#FF0000", "SYSTEM", users[:-2]])
        msg = sender.clientEncryptor.encrypt(msg)
        sender.conn.send(msg)
        return True
    if msg[0] in ["/nick", "/name"]:
        # User wants to change nickname
        try:
            # valid character check
            # if len >= 3, a space was in the name which is not allowed
            if len(msg) < 3 and re.match(r'^[a-zA-Z0-9_]+$', msg[1]):
                if msg[1].lower() in nonAllowedUsernames:
                    # restricted name check
                    sysmsg = serverAlertMessages["NICKILLEGALNAME"]
                elif len(msg[1]) < 3 or len(msg[1]) > 24:
                    sysmsg = serverAlertMessages["NICKBADLENGTH"]
                else:
                    notRepeated = True
                    for c in active_connections:
                        if c.nick.lower() == msg[1].lower():
                            notRepeated = False
                            break
                    # made it through repeat check, name is valid
                    if notRepeated:
                        sender.nick = msg[1]
                        sysmsg = serverAlertMessages["NICKUPDATE"] + sender.nick
                        # TODO: Notify everyone in the server that their name has changed
                    else:
                        sysmsg = serverAlertMessages["NICKREPEAT"]
            else:
                sysmsg = serverAlertMessages["NICKBADCHARS"]
        except IndexError:
            sysmsg = serverAlertMessages["NICKBADARGS"]
        msg = pickle.dumps([True, "#FF0000", "SYSTEM", sysmsg])
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
        msg = pickle.dumps([True, "#FF0000", "SYSTEM", sysmsg])
        msg = sender.clientEncryptor.encrypt(msg)
        sender.conn.send(msg)
    if msg[0] == "/msg":
        # User is attempting to direct message another user on the server
        try:
            target = msg[1]
            if target != sender.nick:
                for c in active_connections:
                    if target == c.nick:
                        # message found
                        formattedMsg = [False, sender.color, "<DM from> " + sender.nick, ' '.join(msg[2:])]
                        formattedMsg = pickle.dumps(formattedMsg)
                        formattedMsg = c.clientEncryptor.encrypt(formattedMsg)
                        c.conn.send(formattedMsg)
                        # mirrors direct message to sender for clarity
                        formattedMsg = [False, sender.color, "<DM to> " + c.nick, ' '.join(msg[2:])]
                        formattedMsg = pickle.dumps(formattedMsg)
                        formattedMsg = sender.clientEncryptor.encrypt(formattedMsg)
                        sender.conn.send(formattedMsg)
                        return True
                sysmsg = serverAlertMessages["DIRECTMESSAGENOUSER"] + msg[1]
            else:
                # Trying to message yourself? Why?
                sysmsg = serverAlertMessages["DIRECTMESSAGESELFMESSAGE"]
        except IndexError:
            sysmsg = serverAlertMessages["DIRECTMESSAGEBADARGS"]
        msg = pickle.dumps([True, "#FF0000", "SYSTEM", sysmsg])
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
            msg_handler(User(None, None, "< SERVER BROADCAST >", None, "#FF0000"),
                        t.nick + serverAlertMessages["USERDISCONNECT"])
    return


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
    # Compare strings here. If encryption was successful, they should be equal.
    goodKeyExchange = (msg == clientDecryptedMessage)
    return clientPublicKey, goodKeyExchange


def serverInputHandler():
    while True:
        serverInput = input()
        if serverInput[0] != "/":
            # not a server command, broadcast message to everyone
            msg_handler(User(None, None, "< SERVER BROADCAST >", None, "#FF0000"), serverInput)
        else:
            # server command
            if serverInput == "/config":
                cfg_file_generator()
            if serverInput == "/users":
                userList = "Connected Users: "
                for c in active_connections:
                    userList += c.nick + ", "
                print(userList[:-2])


# Main
active_connections = []


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        serverKey = RSA.generate(2048)
        serverEncryptor = PKCS1_OAEP.new(serverKey)
        # serverKey contains both private and public key
        print("Server Port:")
        PORT = input()
        PORT = int(PORT)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', PORT))
        s.listen(MAX_CONNECTIONS)
        serverThread = threading.Thread(target=serverInputHandler, args=(), name="Server")
        serverThread.start()
        while True:
            conn, addr = s.accept()
            clientPublicKey, goodKeyExchange = keyExchange(conn, serverKey, serverEncryptor)
            if not goodKeyExchange:
                # Critical error: key exchange failed
                # Notify client, terminate connection and wait for next connection
                msg = pickle.dumps([True, "#FF0000", "SYSTEM", serverAlertMessages["RSAKEYEXCHANGEERROR"]])
                conn.sendall(msg)
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                continue
            # TODO: Password exchange here, after connection is encrypted
            newActiveUser = User(conn, addr, str(addr), clientPublicKey)
            msg_handler(User(None, None, "< SERVER BROADCAST >", None, "#FF0000"),
                        newActiveUser.nick + serverAlertMessages["USERCONNECT"])
            newThread = threading.Thread(target=client_mgr, args=(newActiveUser, serverEncryptor,), name=addr)
            active_connections.append(newActiveUser)
            newThread.start()


if __name__ == "__main__":
    main()
