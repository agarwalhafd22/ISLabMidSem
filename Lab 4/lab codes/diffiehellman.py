from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class DiffieHellmanHospitalSystem:
    def __init__(self):
        self.shared_key = self.diffie_hellman_key_exchange()

    def diffie_hellman_key_exchange(self):
        p = getPrime(128)
        g = 2
        private_key = random.randint(1, p - 1)
        public_key = pow(g, private_key, p)
        other_public_key = pow(g, random.randint(1, p - 1), p)
        shared_secret = pow(other_public_key, private_key, p)
        return shared_secret.to_bytes(16, byteorder='big')

    def aes_encrypt(self, message, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
        return cipher.iv, ciphertext

    def aes_decrypt(self, iv, ciphertext, key):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

    # Doctor can add a record
    def doctor_add_record(self, patient_id, record_data):
        iv, encrypted_record = self.aes_encrypt(record_data, self.shared_key)
        self.records[patient_id] = (iv, encrypted_record)
        print(f"Encrypted Record for {patient_id}: {encrypted_record}")

    # Doctor views the decrypted record
    def doctor_view_record(self, patient_id):
        iv, encrypted_record = self.records.get(patient_id)
        if encrypted_record:
            decrypted_record = self.aes_decrypt(iv, encrypted_record, self.shared_key)
            print(f"Decrypted Record for {patient_id}: {decrypted_record}")
        else:
            print("No record found.")

# Example usage of the hospital system
hospital_dh = DiffieHellmanHospitalSystem()
hospital_dh.doctor_add_record("patient123", "This is confidential patient data.")
hospital_dh.doctor_view_record("patient123")
