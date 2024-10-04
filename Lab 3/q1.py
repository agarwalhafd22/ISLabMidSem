'''
Using RSA, encrypt the message "Asymmetric Encryption" with the public
key (n, e). Then decrypt the ciphertext with the private key (n, d) to verify the
original message.
'''

from Crypto.Util.number import getPrime, inverse, bytes_to_long
from random import randint
from hashlib import sha256
from Crypto.Random import get_random_bytes
from math import gcd



def coprime(nm):
    for i in range(2,nm):
        if gcd(i, nm) == 1:
            return i
    return None

def genkey():
    p=getPrime(128)
    q=getPrime(128)
    n=p*q
    phi_n=(p-1)*(q-1)
    e=coprime(phi_n)
    d=inverse(e,phi_n)
    return p,q,n,e,d

p,q,n,e,d=genkey()
print("Modulus",n)
print("publickey",e)
print("privatekey",d)

def rsa_encrypt(message):
    encrypted_message=[]
    for char in message:
        encrypted_message.append(pow(ord(char),e,n))
    return encrypted_message

def rsa_decrypt(message):
    decrypted=""
    for i in message:
        decrypted+=chr(pow(i,d,n))

    return decrypted

m="Asymmetric Encryption"
ciphertext=rsa_encrypt(m)
print(ciphertext)
decryptedtext=rsa_decrypt(ciphertext)
print(decryptedtext)
