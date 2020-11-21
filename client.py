import pickle
import select
import socket
import threading

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

'''
MESSAGE OBJECTS

A message object going from the client to the server is a 2-list consisting of 

[isSystemMessage, message]

where

isSystemMessage is a Bool that describes whether the server should treat the received message as a control message,
message is a String that contains the message.

A message object going from the server to the client is a 4-list consisting of 

[isSystemMessage, colorCode, messageSender, message]

where
isSystemMessage is a Bool that describes whether the client should treat the received message as a control message,
colorCode is a String containing the hex color code of the message (#FFFFFF if the message is a system message),
messageSender is a String containing the source of the message (SERVER if the message is a system message),
message is a String that contains the message.
'''

HOST = '127.0.0.1'
PORT = 4252


def send_handler(s):
    while True:
        msg = input()
        if msg.startswith("/"):
            if msg == "/quit":
                msgList = [True, "/quit"]
                msg = pickle.dumps(msgList)
                s.send(msg)
                s.shutdown(socket.SHUT_RDWR)
                s.close()
                break
            # sends non-quit command message, continues execution
            msg = pickle.dumps([True, msg])
            s.send(msg)
            continue
        msg = pickle.dumps([False, msg])
        s.send(msg)


def keyExchange(s, clientRSAKeypair, clientEncryptor):
    serverPublicKey = RSA.importKey(s.recv(4096))
    serverEncryptor = PKCS1_OAEP.new(serverPublicKey)
    s.sendall(clientRSAKeypair.publickey().export_key('DER'))
    serverEncMessage = s.recv(4096)
    msg = clientEncryptor.decrypt(serverEncMessage)
    clientEncMessage = serverEncryptor.encrypt(msg)
    s.sendall(clientEncMessage)
    return serverPublicKey

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    clientRSAKeypair = RSA.generate(2048)
    clientEncryptor = PKCS1_OAEP.new(clientRSAKeypair)
    serverPublicKey = keyExchange(s, clientRSAKeypair, clientEncryptor)
    # The client always expects the key exchange to be performed successfully. Unlike the server, the client does not
    # compare the two values. We trust the server to be the authority here, and to notify the client if the handshake
    # was performed incorrectly. In this case, the server notifies the client and terminates the connection as normal.
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
                    data = rs.recv(4096)
                except OSError:
                    # connection terminated (for some reason)
                    break
                if not data:
                    break
                msg = pickle.loads(data)
                print(msg)
