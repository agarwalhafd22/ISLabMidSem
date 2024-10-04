'''
Try using the Elgammal, Schnor asymmetric encryption standard and verify the above steps.
'''

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random
from hashlib import sha256


# ElGamal key generation
def genkey_elgamal():
    p = getPrime(128)  # large modulus p
    e1 = random.randint(2, p - 1)  # base for exponentiation
    d = random.randint(2, p - 2)  # private key
    e2 = pow(e1, d, p)  # public key component e2
    return p, e1, e2, d


# ElGamal encryption
def encrypt_elgamal(message, p, e1, e2):
    r = random.randint(2, p - 2)  # random integer r
    c1 = pow(e1, r, p)  # c1 = e1^r mod p
    m = bytes_to_long(message)  # convert message to a long integer
    c2 = (m * pow(e2, r, p)) % p  # c2 = m * e2^r mod p
    return c1, c2


# ElGamal decryption
def decrypt_elgamal(c1, c2, p, d):
    s = pow(c1, d, p)  # s = c1^d mod p
    s_inverse = inverse(s, p)  # calculate the modular inverse of s mod p
    m = (c2 * s_inverse) % p  # m = c2 * s_inverse mod p
    return long_to_bytes(m)  # convert the long integer back to bytes


# SHA-256 Hashing
def sha256_hash(message):
    return sha256(message).hexdigest()


# Signature generation (ElGamal-like signing)
def elgamal_sign(message, p, e1, d):
    r = random.randint(2, p - 2)
    c1 = pow(e1, r, p)
    h = bytes_to_long(sha256_hash(message).encode())
    s = (h - d * c1) * inverse(r, p - 1) % (p - 1)
    return c1, s


# Signature verification
def elgamal_verify(message, signature, p, e1, e2):
    c1, s = signature
    h = bytes_to_long(sha256_hash(message).encode())
    v1 = pow(e1, h, p)
    v2 = (pow(e2, c1, p) * pow(c1, s, p)) % p
    return v1 == v2

p,e1,e2,d=genkey_elgamal()
message=b"harsh"
c1,c2=encrypt_elgamal(message, p, e1, e2)
print(f"{c1} \n{c2} ")
m=decrypt_elgamal(c1, c2, p, d)
print(m.decode())

