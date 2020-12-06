import configparser
import pickle
import select
import socket
import threading
import tkinter
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showerror

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
    if len(msg) == 0:
        return
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
            msg = serverEncryptor.encrypt(msg)
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
    myFile = askopenfilename(title="Select EasyChat Configuration File",
                             filetypes=(("ECHAT Files", "*.ECHAT"), ("All Files", "*.*")))
    # TODO: Error checking
    try:
        config.read(myFile)
    except configparser.MissingSectionHeaderError:
        showerror(title="Critical Error", message="This isn't an EasyChat configuration file!")
        exit(1)
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
                if msg[0]:
                    message = "<SERVER>: " + msg[3]
                else:
                    message = msg[2] + ": " + msg[3]
                msgList.insert(tkinter.END, message)


def main():
    masterWindow = tkinter.Tk()
    # message window
    msgFrame = tkinter.LabelFrame(masterWindow, text="Messages", padx=5, pady=5)
    msgFrame.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky=tkinter.E + tkinter.W + tkinter.N + tkinter.S)
    scrollbar = tkinter.Scrollbar(msgFrame)
    scrollbar.grid(row=0, column=1, sticky=tkinter.E)
    msglist = tkinter.Listbox(msgFrame, bd=0, yscrollcommand=scrollbar.set, width=100)
    msglist.grid(row=0, column=0, sticky=tkinter.E + tkinter.W + tkinter.N + tkinter.S)

    # message sending
    inputFrame = tkinter.Frame(masterWindow)
    inputFrame.grid(row=1, column=0, sticky=tkinter.W + tkinter.E)
    message_input = tkinter.Entry(inputFrame, width=50)
    message_button = tkinter.Button(inputFrame, text="Send",
                                    command=lambda: send_handler(s, serverEncryptor, message_input))
    message_input.grid(row=0, column=0, columnspan=2, padx=10, pady=10)
    message_button.grid(row=0, column=2, padx=10, pady=10)
    msglist.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=msglist.yview)

    masterWindow.bind(sequence='<Return>', func=lambda event=None: send_handler(s, serverEncryptor, message_input))

    HOST, PORT, PASSWORD, NICK = serverConfigParser()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        masterWindow.title(NICK)
        try:
            s.connect((HOST, int(PORT)))
        except ConnectionRefusedError:
            showerror(title="Critical Error", message="The server refused your connection.")
            exit(1)
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
