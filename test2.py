from Crypto.Util.number import getPrime, inverse, bytes_to_long
from math import gcd
import hashlib
import random
from sympy import isprime


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


class System:

    def finance(self):
        print("Finance Menu")
        while True:
            print("\n1. Send to Supply")
            print("2. Send to HR")
            print("3. Exit")

            choice = input("Choose an option: ")
            if choice == '1':
                print("Enter data to send:")
                data=input()
                ciphertext = rsa_encrypt(data)
                print("Cipher Text: ", ciphertext)
            elif choice == '2':
                print("Enter data to send:")
                data = input()
                ciphertext = rsa_encrypt(data)
                print("Cipher Text: ", ciphertext)
            elif choice == '3':
                break

    def supply(self):
        print("Supply Menu")
        while True:
            print("\n1. Send to Finance")
            print("2. Send to HR")
            print("3. Exit")

            choice = input("Choose an option: ")
            if choice == '1':
                print("Enter data to send:")
                data=input()
                ciphertext = rsa_encrypt(data)
                print("Cipher Text: ", ciphertext)
            elif choice == '2':
                print("Enter data to send:")
                data = input()
                ciphertext = rsa_encrypt(data)
                print("Cipher Text: ",  ciphertext)
            elif choice == '3':
                break

    def hr(self):
        print("HR Menu")
        while True:
            print("\n1. Send to Finance")
            print("2. Send to Supply")
            print("3. Exit")

            choice = input("Choose an option: ")
            if choice == '1':
                print("Enter data to send:")
                data=input()
                ciphertext = rsa_encrypt(data)
                print("Cipher Text: ", ciphertext)
            elif choice == '2':
                print("Enter data to send:")
                data = input()
                ciphertext = rsa_encrypt(data)
                print("Cipher Text: ", ciphertext)
            elif choice == '3':
                break

def main():
    system = System()

    while True:
        print("\nMain Menu")
        print("1. Finance is Sender")
        print("2. Supply is Sender")
        print("3. HR is Sender")
        print("4. Exit")

        choice = input("Choose a role: ")
        if choice == '1':
            system.finance()
        elif choice == '2':
            system.supply()
        elif choice == '3':
            system.hr()
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please choose again.")


if __name__ == '__main__':
    main()