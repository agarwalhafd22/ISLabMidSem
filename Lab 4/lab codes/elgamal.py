from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from Crypto.Hash import SHA256
import random


class ElGamal:
    def __init__(self, bits=256):
        self.p = getPrime(bits)
        self.g = random.randint(2, self.p - 1)  # Generator
        self.x = random.randint(2, self.p - 2)  # Private key
        self.y = pow(self.g, self.x, self.p)  # Public key

    def encrypt(self, plaintext):
        plaintext_long = bytes_to_long(plaintext)
        k = random.randint(2, self.p - 2)  # Random k
        c1 = pow(self.g, k, self.p)
        c2 = (plaintext_long * pow(self.y, k, self.p)) % self.p
        return c1, c2

    def decrypt(self, c1, c2):
        s = pow(c1, self.x, self.p)
        s_inverse = inverse(s, self.p)
        plaintext_long = (c2 * s_inverse) % self.p
        return long_to_bytes(plaintext_long)

    def sign(self, message):
        k = random.randint(2, self.p - 2)
        r = pow(self.g, k, self.p)
        k_inverse = inverse(k, self.p - 1)
        s = (k_inverse * (bytes_to_long(message) + self.x * r)) % (self.p - 1)
        return r, s

    def verify(self, message, signature):
        r, s = signature
        if not (1 <= r < self.p and 1 <= s < self.p - 1):
            return False
        left = (pow(self.g, bytes_to_long(message), self.p) * pow(self.y, r, self.p)) % self.p
        right = pow(r, s, self.p)
        return left == right


class HospitalSystem:
    def __init__(self):
        self.elgamal = ElGamal()
        self.records = {}
        self.hashes = {}

    def add_record(self, patient_id, record_data):
        print("\nDoctor adding record...")
        record_data_bytes = record_data.encode()  # Ensure it's bytes
        encrypted_record = self.elgamal.encrypt(record_data_bytes)
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
            decrypted_record = self.elgamal.decrypt(*encrypted_record)
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
            decrypted_record = self.elgamal.decrypt(*encrypted_record)
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
            decrypted_record = self.elgamal.decrypt(*encrypted_record)
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
hospital_system.add_record("patient123", "Confidential")
hospital_system.update_record("patient123", "Update")
hospital_system.view_record("patient123")

# Nurse can view the decrypted record
hospital_system.nurse_view_record("patient123")

# Admin can verify the hash
hospital_system.verify_hash("patient123")
