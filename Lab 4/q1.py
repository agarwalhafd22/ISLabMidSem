from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.dh import generate_parameters, DHPrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secrets import token_bytes


# Key Management Class
class KeyManager:
    def __init__(self):
        self.keys = {}  # Holds RSA keys for subsystems
        self.dh_params = generate_parameters(generator=2, key_size=2048, backend=default_backend())

    # Generate RSA Keys for a subsystem
    def generate_rsa_keys(self, subsystem_name):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        self.keys[subsystem_name] = {
            'private_key': private_key,
            'public_key': public_key
        }

    # Generate DH key pair for secure communication
    def generate_dh_key_pair(self):
        private_key = self.dh_params.generate_private_key()
        return private_key

    # Fetch public key of a subsystem
    def get_public_key(self, subsystem_name):
        return self.keys[subsystem_name]['public_key']

    # Revoke keys (for future extensions)
    def revoke_keys(self, subsystem_name):
        if subsystem_name in self.keys:
            del self.keys[subsystem_name]


# Communication Class
class SecureCommunication:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    # Securely exchange data using RSA and Diffie-Hellman
    def secure_data_exchange(self, sender, receiver, data):
        # Diffie-Hellman Key Exchange between sender and receiver
        sender_dh_private_key = self.key_manager.generate_dh_key_pair()
        receiver_dh_private_key = self.key_manager.generate_dh_key_pair()

        # Generate shared secret
        sender_shared_key = sender_dh_private_key.exchange(receiver_dh_private_key.public_key())
        receiver_shared_key = receiver_dh_private_key.exchange(sender_dh_private_key.public_key())

        # Derive a shared AES key using HKDF
        shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'SecureCorp Exchange',
            backend=default_backend()
        ).derive(sender_shared_key)

        # Encrypt the data using RSA and AES
        receiver_public_key = self.key_manager.get_public_key(receiver)
        encrypted_data = receiver_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Simulate secure data transmission
        print(f"Data encrypted and securely sent from {sender} to {receiver}")
        return encrypted_data, shared_key

    # Decrypt received data using RSA
    def decrypt_data(self, receiver, encrypted_data, shared_key):
        private_key = self.key_manager.keys[receiver]['private_key']
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Data received by {receiver}: {decrypted_data.decode()}")
        return decrypted_data


# Simulate the Communication System
def main():
    # Initialize Key Manager
    key_manager = KeyManager()

    # Generate RSA keys for subsystems
    key_manager.generate_rsa_keys("Finance System")
    key_manager.generate_rsa_keys("HR System")
    key_manager.generate_rsa_keys("Supply Chain Management")

    # Initialize secure communication handler
    secure_comm = SecureCommunication(key_manager)

    # Example of secure data exchange between Finance and HR systems
    message = b"Employee Payroll for Q1"
    encrypted_message, shared_key = secure_comm.secure_data_exchange("Finance System", "HR System", message)

    # HR system decrypts the received data
    secure_comm.decrypt_data("HR System", encrypted_message, shared_key)


if __name__ == "__main__":
    main()
