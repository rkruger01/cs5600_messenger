import socket
import threading
import select
import pickle
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
            #sends non-quit command message, continues execution
            msg = pickle.dumps([True, msg])
            s.send(msg)
            continue
        msg = pickle.dumps([False, msg])
        s.send(msg)


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
                msg = pickle.loads(data)
                print(msg)
