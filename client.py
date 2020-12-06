import configparser
import pickle
import select
import socket
import threading
import tkinter
from tkinter.filedialog import askopenfilename

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


def send_handler(s, serverEncryptor: PKCS1OAEP_Cipher, entryObject: tkinter.Entry):
    msg = entryObject.get()
    entryObject.delete(0, 'end')
    if msg.startswith("/"):
        if msg == "/quit":
            msgList = [True, "/quit"]
            msgDump = pickle.dumps(msgList)
            formattedMsg = serverEncryptor.encrypt(msgDump)
            s.send(formattedMsg)
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            quit(0)
        else:
            # sends non-quit command message, continues execution
            msg = pickle.dumps([True, msg])
            s.send(msg)
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
    myFile = askopenfilename()
    config.read(myFile)
    return config['SERVER']['ServerIP'], config['SERVER']['ServerPORT'], config['SERVER']['ServerPASSWORD'], \
           config['SERVER']['ServerNICKNAME']


def listener(msgList: tkinter.Listbox, s: socket, clientEncryptor: PKCS1OAEP_Cipher):
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
                # TODO: HANDLE MESSAGE FORMATTING HERE
                msgList.insert(tkinter.END, msg)


def main():
    gui = tkinter.Tk()
    chat_frame = tkinter.Frame(master=gui, width=100, height=200, bg="red")
    chat_frame.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
    scrollbar = tkinter.Scrollbar(chat_frame)
    scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
    msglist = tkinter.Listbox(gui, bd=0, yscrollcommand=scrollbar.set, width=100)
    msglist.pack(fill=tkinter.X)
    message_input = tkinter.Entry(gui, width=50)
    message_button = tkinter.Button(gui, text="Send",
                                    command=lambda: send_handler(s, serverEncryptor, message_input))
    gui.bind(sequence='<Return>', func=lambda event=None: send_handler(s, serverEncryptor, message_input))
    message_input.pack()
    message_button.pack()
    msglist.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=msglist.yview)
    HOST, PORT, PASSWORD, NICK = serverConfigParser()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        gui.title(NICK)
        s.connect((HOST, int(PORT)))
        clientRSAKeypair = RSA.generate(2048)
        clientEncryptor = PKCS1_OAEP.new(clientRSAKeypair)
        serverEncryptor = keyExchange(s, clientRSAKeypair, clientEncryptor)
        # The client always expects the key exchange to be performed successfully. Unlike the server, the client does
        # not compare the two values. We trust the server to be the authority here, and to notify the client if the
        # handshake was performed incorrectly. In this case, the server notifies the client and terminates the
        # connection as normal.

        # launches server listener thread for incoming messages
        receiver = threading.Thread(target=listener, args=(msglist, s, clientEncryptor,))
        receiver.start()
        tkinter.mainloop()


if __name__ == "__main__":
    main()
