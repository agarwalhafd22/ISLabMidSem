import random
import time
import json
import os
from Crypto.Util import number
from Crypto.Hash import SHA256
from Crypto.PublicKey import ElGamal
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime, timedelta


class KeyManagementService:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.master_private_key, self.master_public_key = self.generate_key_pair()
        self.content_access = {}
        self.logs = []
        self.renewal_interval = timedelta(days=730)  # 24 months
        self.last_renewal = datetime.now()

    def generate_key_pair(self):
        key = ElGamal.generate(self.key_size)
        return key, key.publickey()

    def encrypt_content(self, content):
        cipher = PKCS1_OAEP.new(self.master_public_key)
        encrypted_content = cipher.encrypt(content.encode())
        return encrypted_content

    def store_key(self, key, filename):
        with open(filename, 'wb') as f:
            f.write(key.export_key(format='PEM'))

    def load_key(self, filename):
        with open(filename, 'rb') as f:
            return ElGamal.import_key(f.read())

    def renew_keys(self):
        self.master_private_key, self.master_public_key = self.generate_key_pair()
        self.last_renewal = datetime.now()
        self.logs.append(f"Keys renewed at {self.last_renewal.isoformat()}")

    def log_activity(self, message):
        self.logs.append(f"{datetime.now().isoformat()}: {message}")

    def grant_access(self, customer_id, content_id, expiry_time):
        self.content_access[content_id] = {
            "customer_id": customer_id,
            "expiry_time": expiry_time
        }
        self.log_activity(f"Granted access to {customer_id} for {content_id} until {expiry_time}")

    def revoke_access(self, customer_id, content_id):
        if content_id in self.content_access:
            del self.content_access[content_id]
            self.log_activity(f"Revoked access for {customer_id} to {content_id}")

    def check_access(self, customer_id, content_id):
        if content_id in self.content_access:
            access_info = self.content_access[content_id]
            if access_info['customer_id'] == customer_id:
                if datetime.now() < access_info['expiry_time']:
                    return True
        return False

    def audit_logs(self):
        return self.logs


# Example usage of the KeyManagementService
if __name__ == "__main__":
    kms = KeyManagementService()

    # Encrypt content
    content = "This is a secret message for digital content."
    encrypted_content = kms.encrypt_content(content)

    # Store the master private key securely
    kms.store_key(kms.master_private_key, "master_private_key.pem")

    # Grant access to a customer
    expiry_time = datetime.now() + timedelta(days=30)  # 30 days from now
    kms.grant_access("customer_123", "content_456", expiry_time)

    # Check access
    if kms.check_access("customer_123", "content_456"):
        print("Access granted to customer_123 for content_456")
    else:
        print("Access denied")

    # Revoke access
    kms.revoke_access("customer_123", "content_456")

    # Renew keys if necessary
    if datetime.now() - kms.last_renewal > kms.renewal_interval:
        kms.renew_keys()

    # Audit logs
    for log in kms.audit_logs():
        print(log)
