import socket
import time
import struct
from telnetlib import Telnet
import threading
import queue
from ecdsa import SigningKey, VerifyingKey
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto import Random
import base64
import binascii
import OpenSSL
import itertools
check = [0]
HOST = '0.0.0.0'
PORT = 2222

data_queue = queue.Queue()
#data_queue.put("xtest")
#data_queue.put("optee_example_hello_world")
#data_queue.put("optee_example_hello_world")
lock = threading.Lock()

PEM_public = ("""-----BEGIN RSA PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL5c51/v1osjr5+lRPykmpQKyGdXMG0g
S6Du1l8Hm0qYXc+azq6qqZvr39zeufw/VLKTfeKeKVJX1D28TImn6cUCAwEAAQ==
-----END RSA PUBLIC KEY-----""")

PEM_private = ("""-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAL5c51/v1osjr5+lRPykmpQKyGdXMG0gS6Du1l8Hm0qYXc+azq6q
qZvr39zeufw/VLKTfeKeKVJX1D28TImn6cUCAwEAAQJASDCJGculK6zDzCHrkHeH
mz6fkvjwh2Go7IXGS9FhpZ6Lx6FacvAEyARdXlIYXNRogiEX3aHMQoflhOFYIMID
fQIhAPj4koWd11bSLeR5bI1ojNm/M7y6oKYiWlX/Txbo66L7AiEAw7y+czu2VIdK
qcUfGnLfI9qVrZPhw4rB14/3oOBXCj8CIQC5yINNwaLW3q/wNcuTGdlBAzSQOJN4
ZVoTohhaeCSd0QIgGqi0T8GMPcsHckP0zodiuOFmjXOcxiM574AeO/0SHcUCICkw
Ztd6hrPK/M6HFQL/fGu1MecHNrsKyroMlZNqLmXu
-----END RSA PRIVATE KEY-----""");


def socket_connect(HOST, PORT):
    client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    return client_socket

def socket_close(client_socket):
    client_socket.close()

def socket_active(client_socket,message,i):
    lock.acquire()
    check[i] = 1

    #client_socket.send(message.encode())
    message = message.encode()
    m,digest = sign(message)
    #m = encry_rsa(sig, message)
    client_socket.send(m)
    time.sleep(5)
    #client_socket.send(digest)
    print(digest.hexdigest().encode())
    client_socket.send(digest.hexdigest().encode())
    #data = client_socket.recv(1024)
    #size = data.decode().replace("\x00","")
    #print(size)
    #client_socket.send('result'.encode())
    #time.sleep(1)
    
    #data = ''
    #while True:
    #    #time.sleep(5)
    #    part = client_socket.recv(4096)
    #    data += part.decode()
        #data += str(part)
    #    if len(part) < 4096:
    #        break
    #now = time.gmtime(time.time())
    #f = open('./optee_result/'+str(now.tm_hour)+"_"+str(now.tm_min)+"_"+str(now.tm_sec)+"_id_pw.txt",'a')
    #f.write(data)
    #f.close()
    check[i] = 0
    #time.sleep(3)
    lock.release()

    #print("\n\n"+message+"\nresult\n"+data+"\n\n")
    #socket_close(client_socket)

def socket_loop(s,m, i):
    #s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    #s.connect((HOST, PORT))
    socket_active(s,m,i)
    #time.sleep(1)
    #s.close()

def socket_watch(data_queue, s):
    while(1):
         
        if data_queue.qsize() > 0:
            for i in range(len(check)):
                if check[i] == 0:
                    m = data_queue.get()
                    #time.sleep(7)
                    t = threading.Thread(target=socket_loop, args=(s,m,i))
                    t.start()
                    if m == 'exit ':
                        exit(1)

def sign(message):
    now = time.gmtime(time.time())
    digest = SHA.new()
    digest.update(message)

    k = RSA.import_key(PEM_private)

    #cipher = PKCS1_OAEP.new(k)
    cipher = PKCS1_v1_5.new(k)
    cipher_text =  cipher.sign(digest)
    #print(len(cipher_text))
    k = RSA.import_key(PEM_public)
    print(cipher_text.upper())
    
    #cipher = PKCS1_OAEP.new(k)
    cipher = PKCS1_v1_5.new(k)
    m = cipher.verify(digest,cipher_text)
    #print(digest.hexdigest())
    #print(len(digest))
    print(m)
    return cipher_text, digest

def encry_rsa(sig, message):
    with open("./key/rsa_server_pub.pem","r") as f:
        pub = RSA.import_key(f.read())
    
    m = sig

    enc_message = pub.encrypt(m,Crypto.Cipher.PKCS1_OAEP)

    return enc_message

def socket_input():
    while(1):
        id_ = input('Enter ID : ')
        pw = input('Enter Password : ')
        message = id_ + pw
        if message == 'exit ':
            data_queue.put(message)
            break
        elif message == 'list ':
            for i in range(len(check)):
                print(check[i])
            print(list(data_queue.queue))
        elif message == 'null ':
            for i in range(len(check)):
                check[i] = 0
            while(data_queue.qsize()>0):
                data_queue.get()

        else:
            data_queue.put(message)



s = socket_connect(HOST, PORT)
t_watch = threading.Thread(target=socket_watch, args=(data_queue,s))
t_watch.start()

t = threading.Thread(target=socket_input, args=())
t.start()

'''
while(1):
    message = input('Enter Message : ')
    if message == 'exit':
        break
    elif message == 'list':
        for i in range(len(check)):
            print(check[i])
        print(list(data_queue.queue))

    else:
        data_queue.put(message)
'''
        #for i in range(len(check)):
        #    if check[i] == 0:
        #        m = data_queue.get()
        #        t = threading.Thread(target=socket_loop, args=(s,m,i))
        #        t.start()
    #if data_queue.qsize > 0:
    #    for i in range(len(check)):
    #        if check[i] == 0:
    #            m = data_queue.get()
    #            t = threading.Thread(target=socket_loop, args=(s,m,i))
    #            t.start()

#while(1):
#    message = input('Enter Message : ')
#    if message == 'exit':
#        break
#    socket_active(s_1,message)
#t = threading.Thread(target=socket_loop, args=())
#t.start()
