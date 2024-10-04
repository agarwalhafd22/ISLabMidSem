from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class HospitalSystemRSA:
    def __init__(self):
        self.records = {}
        self.hashes = {}
        self.signatures = {}
        self.doctor_private, self.doctor_public = self.generate_rsa_key_pair()
        self.nurse_private, self.nurse_public = self.generate_rsa_key_pair()
        self.admin_private, self.admin_public = self.generate_rsa_key_pair()

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

    def sha256(self, message):
        h = SHA256.new(message)
        return h.hexdigest()

    # Doctor can add a record
    def doctor_add_record(self, patient_id, record_data):
        print("\nDoctor adding record...")
        record_data_bytes = record_data.encode()
        encrypted_record = self.rsa_encrypt(record_data_bytes, self.doctor_public)
        record_hash = self.sha256(record_data_bytes)
        signature = self.rsa_sign(record_data_bytes, self.doctor_private)

        self.records[patient_id] = encrypted_record
        self.hashes[patient_id] = record_hash
        self.signatures[patient_id] = signature

        print(f"Encrypted Record for {patient_id}: {encrypted_record}")
        print(f"Record Hash: {record_hash}")
        print(f"Record Signature: {signature.hex()}")

    # Doctor views the decrypted record
    def doctor_view_record(self, patient_id):
        print("\nDoctor viewing record...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = self.rsa_decrypt(encrypted_record, self.doctor_private)
            print(f"Decrypted Record for {patient_id}: {decrypted_record.decode()}")
        else:
            print("No record found.")

    # Nurse verifies the hash of the record
    def nurse_verify_hash(self, patient_id):
        print("\nNurse verifying record hash...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = self.rsa_decrypt(encrypted_record, self.doctor_private)
            computed_hash = self.sha256(decrypted_record)
            stored_hash = self.hashes.get(patient_id)
            if computed_hash == stored_hash:
                print(f"Record hash for {patient_id} is valid.")
            else:
                print(f"Record hash for {patient_id} is invalid.")
        else:
            print("No record found.")

    # Admin views encrypted record
    def admin_view_encrypted_record(self, patient_id):
        print("\nAdmin viewing encrypted record...")
        encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            print(f"Encrypted Record for {patient_id}: {encrypted_record}")
        else:
            print("No record found.")

    # Admin verifies the record's signature
    def admin_verify_signature(self, patient_id):
        print("\nAdmin verifying signature...")
        encrypted_record = self.records.get(patient_id)
        signature = self.signatures.get(patient_id)
        if encrypted_record and signature:
            decrypted_record = self.rsa_decrypt(encrypted_record, self.doctor_private)
            if self.rsa_verify(decrypted_record, signature, self.doctor_public):
                print(f"Signature for {patient_id} is valid.")
            else:
                print(f"Signature for {patient_id} is invalid.")
        else:
            print("No record or signature found.")

# Example usage of the hospital system
hospital = HospitalSystemRSA()
hospital.doctor_add_record("patient123", "This is confidential patient data.")
hospital.doctor_view_record("patient123")
hospital.nurse_verify_hash("patient123")
hospital.admin_view_encrypted_record("patient123")
hospital.admin_verify_signature("patient123")