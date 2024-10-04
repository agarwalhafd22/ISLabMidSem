from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from Crypto.Hash import SHA256
import random


class Rabin:
    def __init__(self, bits=256):
        self.p = getPrime(bits)
        self.q = getPrime(bits)
        self.n = self.p * self.q  # Modulus

    def encrypt(self, plaintext):
        plaintext_long = bytes_to_long(plaintext)
        if plaintext_long >= self.n:
            raise ValueError("Plaintext must be less than n.")
        # Use a random value to form a valid Rabin encryption
        r = random.randint(1, self.n - 1)
        # Encrypt using the quadratic residue method
        c = (plaintext_long**2 + r * self.n) % self.n  # Proper Rabin encryption
        return c

    def decrypt(self, c):
        m1 = (c % self.p) ** ((self.p + 1) // 4) % self.p  # Using the square root mod p
        m2 = (c % self.q) ** ((self.q + 1) // 4) % self.q  # Using the square root mod q
        r = inverse(self.p, self.q)
        s = inverse(self.q, self.p)
        m = (m1 * self.q * s + m2 * self.p * r) % self.n
        return long_to_bytes(m)

    def sign(self, message):
        message_long = bytes_to_long(message)
        r = random.randint(1, self.n - 1)
        # Sign the message correctly
        signature = (message_long**2 + r * self.n) % self.n  # Proper signature creation
        return signature

    def verify(self, message, signature):
        message_long = bytes_to_long(message)
        # Verify if the signature is a valid quadratic residue
        expected_signature = (message_long**2) % self.n
        return signature == expected_signature


class HospitalSystem:
    def __init__(self):
        self.rabin = Rabin()
        self.records = {}
        self.hashes = {}

    def add_record(self, patient_id, record_data):
        print("\nDoctor adding record...")
        record_data_bytes = record_data.encode()  # Ensure it's bytes
        encrypted_record = self.rabin.encrypt(record_data_bytes)
        record_hash = self.sha256(record_data_bytes)

        self.records[patient_id] = encrypted_record
        self.hashes[patient_id] = record_hash

        print(f"Encrypted Record for {patient_id}: {encrypted_record}")
        print(f"Record Hash: {record_hash}")

    def update_record(self, patient_id, new_record_data):
        print("\nDoctor updating record...")
        if patient_id in self.records:
            self.add_record(patient_id, new_record_data)  # Re-add the new record
        else:
            print("Record not found.")

    def view_record(self, patient_id):
        print("\nDoctor viewing record...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = self.rabin.decrypt(encrypted_record)
            try:
                print(f"Decrypted Record for {patient_id}: {decrypted_record.decode('utf-8')}")
            except UnicodeDecodeError:
                print(f"Decrypted Record for {patient_id}: (binary data, length {len(decrypted_record)})")
        else:
            print("No record found.")

    def nurse_view_record(self, patient_id):
        print("\nNurse viewing record...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = self.rabin.decrypt(encrypted_record)
            try:
                print(f"Decrypted Record for {patient_id}: {decrypted_record.decode('utf-8')}")
            except UnicodeDecodeError:
                print(f"Decrypted Record for {patient_id}: (binary data, length {len(decrypted_record)})")
        else:
            print("No record found.")

    def verify_hash(self, patient_id):
        print("\nVerifying record hash...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = self.rabin.decrypt(encrypted_record)
            computed_hash = self.sha256(decrypted_record)
            stored_hash = self.hashes.get(patient_id)
            if computed_hash == stored_hash:
                print(f"Record hash for {patient_id} is valid.")
            else:
                print(f"Record hash for {patient_id} is invalid.")
        else:
            print("No record found.")

    @staticmethod
    def sha256(message):
        h = SHA256.new(message)
        return h.hexdigest()


# Example usage of the hospital system
hospital_system = HospitalSystem()
hospital_system.add_record("patient123", "This is confidential patient data.")
hospital_system.update_record("patient123", "This is updated confidential patient data.")
hospital_system.view_record("patient123")

# Nurse can view the decrypted record
hospital_system.nurse_view_record("patient123")

# Verify the hash
hospital_system.verify_hash("patient123")
