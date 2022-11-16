from json import dumps, loads
from base64 import b64encode, b64decode
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


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


data = b"hello"

x = encrypt(b"asdfasdfasdfasdf", data)
#for i in x:
    #print(i)
#decrypt(x[0], x[1], b64encode(b"asdfasdfasdfasdf").decode('utf-8')[::-1], x[2])

import datetime

y = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%Z")

#print(y)


