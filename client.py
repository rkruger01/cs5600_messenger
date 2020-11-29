import configparser
import os
import pickle
import select
import socket
import threading

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
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


def send_handler(s, serverEncryptor: PKCS1OAEP_Cipher):
    while True:
        msg = input()
        if msg.startswith("/"):
            if msg == "/quit":
                msgList = [True, "/quit"]
                msg = pickle.dumps(msgList)
                msg = serverEncryptor.encrypt(msg)
                s.send(msg)
                s.shutdown(socket.SHUT_RDWR)
                s.close()
                break
            # sends non-quit command message, continues execution
            msg = pickle.dumps([True, msg])
        else:
            msg = pickle.dumps([False, msg])
        msg = serverEncryptor.encrypt(msg)
        s.send(msg)


def keyExchange(s, clientRSAKeypair, clientEncryptor):
    serverPublicKey = RSA.importKey(s.recv(4096))
    serverEncryptor = PKCS1_OAEP.new(serverPublicKey)
    s.sendall(clientRSAKeypair.publickey().export_key('DER'))
    serverEncMessage = s.recv(4096)
    msg = clientEncryptor.decrypt(serverEncMessage)
    clientEncMessage = serverEncryptor.encrypt(msg)
    s.sendall(clientEncMessage)
    return serverEncryptor


def serverConfigParser():
    config = configparser.ConfigParser()
    configFileList = [x for x in os.listdir('.') if os.path.isfile(os.path.join('.', x)) and x.endswith('.echat')]
    for f in configFileList:
        # If there are multiple configuration files, choose the correct one here
        config.read(f)
        print(config['SERVER']['serverNICKNAME'])
    return config['SERVER']['ServerIP'], config['SERVER']['ServerPORT'], config['SERVER']['ServerPASSWORD'], \
           config['SERVER']['ServerNICKNAME']


def main():
    HOST, PORT, PASSWORD, NICK = serverConfigParser()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, int(PORT)))
        clientRSAKeypair = RSA.generate(2048)
        clientEncryptor = PKCS1_OAEP.new(clientRSAKeypair)
        serverEncryptor = keyExchange(s, clientRSAKeypair, clientEncryptor)
        # The client always expects the key exchange to be performed successfully. Unlike the server, the client does
        # not compare the two values. We trust the server to be the authority here, and to notify the client if the
        # handshake was performed incorrectly. In this case, the server notifies the client and terminates the
        # connection as normal.
        sender = threading.Thread(target=send_handler, args=(s, serverEncryptor))
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
                    msg = clientEncryptor.decrypt(data)
                    msg = pickle.loads(msg)
                    print(msg)


if __name__ == "__main__":
    main()
