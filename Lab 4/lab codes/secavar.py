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


# Hospital System Setup
class HospitalSystemElGamal:
    def __init__(self):
        # Generate ElGamal keys for doctor, nurse, and admin
        self.p, self.e1, self.doctor_e2, self.doctor_d = genkey_elgamal()
        self.p, self.e1, self.nurse_e2, self.nurse_d = genkey_elgamal()
        self.p, self.e1, self.admin_e2, self.admin_d = genkey_elgamal()

        self.records = {}  # Stores encrypted records
        self.hashes = {}  # Stores record hashes for integrity checks
        self.signatures = {}  # Stores signatures for verification

    # Doctor: Add/Update Records (Encrypted & Signed)
    def doctor_add_record(self, patient_id, record_data):
        print("\nDoctor adding record...")
        record_data_bytes = record_data.encode()

        # Encrypt the record using ElGamal
        c1, c2 = encrypt_elgamal(record_data_bytes, self.p, self.e1, self.doctor_e2)

        # Generate a SHA-256 hash for the record
        record_hash = sha256_hash(record_data_bytes)

        # Sign the record with the doctor's private key
        signature = elgamal_sign(record_data_bytes, self.p, self.e1, self.doctor_d)

        # Store the encrypted record, hash, and signature
        self.records[patient_id] = (c1, c2)
        self.hashes[patient_id] = record_hash
        self.signatures[patient_id] = signature

        print(f"Encrypted Record for {patient_id}: (c1: {c1}, c2: {c2})")
        print(f"Record Hash: {record_hash}")
        print(f"Record Signature: {signature}")

    # Doctor: View Decrypted Records
    def doctor_view_record(self, patient_id):
        print("\nDoctor viewing record...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            c1, c2 = encrypted_record
            decrypted_record = decrypt_elgamal(c1, c2, self.p, self.doctor_d)
            print(f"Decrypted Record for {patient_id}: {decrypted_record.decode()}")
        else:
            print("No record found.")

    # Nurse: Verify Record Hash
    def nurse_verify_hash(self, patient_id):
        print("\nNurse verifying record hash...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            c1, c2 = encrypted_record
            decrypted_record = decrypt_elgamal(c1, c2, self.p, self.doctor_d)
            computed_hash = sha256_hash(decrypted_record)
            stored_hash = self.hashes.get(patient_id)
            if computed_hash == stored_hash:
                print(f"Record hash for {patient_id} is valid.")
            else:
                print(f"Record hash for {patient_id} is invalid.")
        else:
            print("No record found.")

    # Nurse: View Decrypted Record
    def nurse_view_record(self, patient_id):
        print("\nNurse viewing decrypted record...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            c1, c2 = encrypted_record
            decrypted_record = decrypt_elgamal(c1, c2, self.p, self.doctor_d)
            print(f"Decrypted Record for {patient_id}: {decrypted_record.decode()}")
        else:
            print("No record found.")

    # Admin: View Encrypted Record & Verify Signature
    def admin_view_encrypted_record(self, patient_id):
        print("\nAdmin viewing encrypted record...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            print(f"Encrypted Record for {patient_id}: {encrypted_record}")
        else:
            print("No record found.")

    # Admin: Verify Record Signature
    def admin_verify_signature(self, patient_id):
        print("\nAdmin verifying signature...")
        encrypted_record = self.records.get(patient_id)
        signature = self.signatures.get(patient_id)
        if encrypted_record and signature:
            c1, c2 = encrypted_record
            decrypted_record = decrypt_elgamal(c1, c2, self.p, self.doctor_d)
            if elgamal_verify(decrypted_record, signature, self.p, self.e1, self.doctor_e2):
                print(f"Signature for {patient_id} is valid.")
            else:
                print(f"Signature for {patient_id} is invalid.")
        else:
            print("No record or signature found.")


# Example usage of the hospital system using ElGamal
hospital_elgamal = HospitalSystemElGamal()

# Doctor adds a record
hospital_elgamal.doctor_add_record("patient123", "This is confidential patient data.")

# Doctor views the decrypted record
hospital_elgamal.doctor_view_record("patient123")

# Nurse verifies the hash of the record
hospital_elgamal.nurse_verify_hash("patient123")

# Nurse views the decrypted record
hospital_elgamal.nurse_view_record("patient123")

# Admin views the encrypted record
hospital_elgamal.admin_view_encrypted_record("patient123")

# Admin verifies the signature of the record
hospital_elgamal.admin_verify_signature("patient123")
