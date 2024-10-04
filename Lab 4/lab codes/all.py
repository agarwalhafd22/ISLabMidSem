from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import random
from sympy import isprime, mod_inverse


# ElGamal Encryption Class
class ElGamal:
    def __init__(self):
        self.p = self.generate_large_prime()
        self.g = random.randint(2, self.p - 1)
        self.private_key = random.randint(1, self.p - 2)
        self.public_key = pow(self.g, self.private_key, self.p)

    def generate_large_prime(self):
        while True:
            num = random.randint(1000, 2000)
            if isprime(num):
                return num

    def encrypt(self, message):
        y = random.randint(1, self.p - 2)
        c1 = pow(self.g, y, self.p)
        c2 = (message * pow(self.public_key, y, self.p)) % self.p
        return (c1, c2)

    def decrypt(self, ciphertext):
        c1, c2 = ciphertext
        s = pow(c1, self.private_key, self.p)
        s_inv = mod_inverse(s, self.p)
        return (c2 * s_inv) % self.p


# Rabin Encryption Class
class Rabin:
    def __init__(self):
        self.p = self.generate_large_prime()
        self.q = self.generate_large_prime()
        self.n = self.p * self.q

    def generate_large_prime(self):
        while True:
            num = random.randint(1000, 2000)
            if isprime(num):
                return num

    def encrypt(self, message):
        return (message ** 2) % self.n

    def decrypt(self, ciphertext):
        r1 = pow(ciphertext, (self.p + 1) // 4, self.p)
        r2 = (self.p - r1) % self.p
        s1 = pow(ciphertext, (self.q + 1) // 4, self.q)
        s2 = (self.q - s1) % self.q

        return [(r1 + r2 * self.q) % self.n,
                (r1 + s2 * self.q) % self.n,
                (s1 + r2 * self.p) % self.n,
                (s1 + s2 * self.p) % self.n]


# Hospital Management System Class
class HospitalSystem:
    def __init__(self):
        # Initialize RSA keys
        print("Initializing RSA...")
        self.records_rsa = {}

        # Initialize ElGamal
        print("Initializing ElGamal...")
        self.elgamal_system = ElGamal()

    # RSA Methods
    def generate_rsa_key_pair(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    def rsa_encrypt(self, message, public_key):
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.encrypt(message)

    def rsa_decrypt(self, encrypted_message, private_key):
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.decrypt(encrypted_message)

    def rsa_sign(self, message, private_key):
        rsa_key = RSA.import_key(private_key)
        h = SHA256.new(message)
        return pkcs1_15.new(rsa_key).sign(h)

    def rsa_verify(self, message, signature, public_key):
        rsa_key = RSA.import_key(public_key)
        h = SHA256.new(message)
        try:
            pkcs1_15.new(rsa_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    # ElGamal Methods
    def add_record_elgamal(self, patient_id, record_data):
        print("\nAdding record using ElGamal...")

        record_data_bytes = record_data.encode()

        # Convert bytes to an integer for ElGamal encryption
        message_int = int.from_bytes(record_data_bytes.ljust(256), byteorder='big')  # Ensure proper size

        encrypted_record = self.elgamal_system.encrypt(message_int)

        # Store encrypted record
        self.records_rsa[patient_id] = encrypted_record

        print(f"Encrypted Record for {patient_id} using ElGamal: {encrypted_record}")


def view_record_elgamal(self, patient_id):
    print("\nViewing record using ElGamal...")

    encrypted_record = self.records_rsa.get(patient_id)

    if encrypted_record:
        decrypted_message_int = self.elgamal_system.decrypt(encrypted_record)

        # Convert integer back to bytes and decode to string
        decrypted_record_bytes = decrypted_message_int.to_bytes((decrypted_message_int.bit_length() + 7) // 8,
                                                                byteorder='big')

        # Handle potential issues with empty bytes or invalid UTF-8 sequences.
        try:
            print(f"Decrypted Record for {patient_id} using ElGamal: {decrypted_record_bytes.decode()}")
            return decrypted_record_bytes.decode()
        except UnicodeDecodeError:
            print("Decrypted data is not valid UTF-8.")
            return None

    else:
        print("No record found.")


# Example usage of the hospital system with all encryption methods integrated
hospital_system = HospitalSystem()

# Using RSA to add a record (for demonstration purposes; you can implement similar methods as above for RSA).
doctor_private_rsa, doctor_public_rsa = hospital_system.generate_rsa_key_pair()
record_data_rsa = "This is confidential patient data."
encrypted_rsa_record = hospital_system.rsa_encrypt(record_data_rsa.encode(), doctor_public_rsa)

print(f"\nEncrypted Record using RSA: {encrypted_rsa_record.hex()}")

# Add and view a record using ElGamal encryption.
hospital_system.add_record_elgamal("patient123", "This is confidential patient data.")
hospital_system.view_record_elgamal("patient123")