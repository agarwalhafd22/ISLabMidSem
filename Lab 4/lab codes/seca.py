from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# RSA Key Generation
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


# RSA Encryption
def rsa_encrypt(message, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(message)


# RSA Decryption
def rsa_decrypt(encrypted_message, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(encrypted_message)


# RSA Signing
def rsa_sign(message, private_key):
    rsa_key = RSA.import_key(private_key)
    h = SHA256.new(message)
    signature = pkcs1_15.new(rsa_key).sign(h)
    return signature


# RSA Signature Verification
def rsa_verify(message, signature, public_key):
    rsa_key = RSA.import_key(public_key)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(rsa_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# SHA-256 Hashing
def sha256(message):
    h = SHA256.new(message)
    return h.hexdigest()


# Hospital System Setup
class HospitalSystem:
    def __init__(self):
        self.records = {}  # Stores encrypted records
        self.hashes = {}  # Stores record hashes for integrity checks
        self.signatures = {}  # Stores signatures for verification
        self.doctor_private, self.doctor_public = generate_rsa_key_pair()
        self.nurse_private, self.nurse_public = generate_rsa_key_pair()
        self.admin_private, self.admin_public = generate_rsa_key_pair()

    # Doctor: Add/Update Records (Encrypted & Signed)
    def doctor_add_record(self, patient_id, record_data):
        print("\nDoctor adding record...")
        record_data_bytes = record_data.encode()

        # Encrypt the record using doctor's public key
        encrypted_record = rsa_encrypt(record_data_bytes, self.doctor_public)

        # Generate a SHA-256 hash for the record
        record_hash = sha256(record_data_bytes)

        # Sign the record with the doctor's private key
        signature = rsa_sign(record_data_bytes, self.doctor_private)

        # Store the encrypted record, hash, and signature
        self.records[patient_id] = encrypted_record
        self.hashes[patient_id] = record_hash
        self.signatures[patient_id] = signature

        print(f"Encrypted Record for {patient_id}: {encrypted_record}")
        print(f"Record Hash: {record_hash}")
        print(f"Record Signature: {signature.hex()}")

    # Doctor: View Decrypted Records
    def doctor_view_record(self, patient_id):
        print("\nDoctor viewing record...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = rsa_decrypt(encrypted_record, self.doctor_private)
            print(f"Decrypted Record for {patient_id}: {decrypted_record.decode()}")
        else:
            print("No record found.")

    # Nurse: Verify Record Hash
    def nurse_verify_hash(self, patient_id):
        print("\nNurse verifying record hash...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = rsa_decrypt(encrypted_record, self.doctor_private)
            computed_hash = sha256(decrypted_record)
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
            decrypted_record = rsa_decrypt(encrypted_record, self.doctor_private)
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
            decrypted_record = rsa_decrypt(encrypted_record, self.doctor_private)
            if rsa_verify(decrypted_record, signature, self.doctor_public):
                print(f"Signature for {patient_id} is valid.")
            else:
                print(f"Signature for {patient_id} is invalid.")
        else:
            print("No record or signature found.")


# Example usage of the hospital system
hospital = HospitalSystem()

# Doctor adds a record
hospital.doctor_add_record("patient123", "This is confidential patient data.")

# Doctor views the decrypted record
hospital.doctor_view_record("patient123")

# Nurse verifies the hash of the record
hospital.nurse_verify_hash("patient123")

# Nurse views the decrypted record
hospital.nurse_view_record("patient123")

# Admin views the encrypted record
hospital.admin_view_encrypted_record("patient123")

# Admin verifies the signature of the record
hospital.admin_verify_signature("patient123")
