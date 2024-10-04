#not working


from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import base64
import os
import json
from datetime import datetime, timedelta

class DRMSystem:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.master_key = None
        self.master_key_expiry = None
        self.customers_access = {}  # Mapping of customer_id to access details
        self.logs = []
        self.init_key_generation()

    # Logging system
    def log_event(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp}: {message}"
        self.logs.append(log_entry)
        print(log_entry)

    # Generate ElGamal key pair (configurable size)
    def init_key_generation(self):
        self.master_key = ElGamal.generate(self.key_size, get_random_bytes)
        self.master_key_expiry = datetime.now() + timedelta(days=24 * 30 * 12)  # 24 months
        self.store_private_key()  # Secure storage of the private key
        self.log_event(f"Generated new master key pair with key size: {self.key_size} bits")

    def store_private_key(self):
        # For simplicity, storing in a file (could be in a secure vault in real-world systems)
        with open("master_private_key.pem", "wb") as f:
            f.write(self.master_key.export_key(format='PEM'))
        self.log_event(f"Stored master private key securely.")

    def load_private_key(self):
        # Load private key from storage
        with open("master_private_key.pem", "rb") as f:
            private_key = ElGamal.import_key(f.read())
        return private_key

    def renew_key_pair(self):
        if datetime.now() > self.master_key_expiry:
            self.init_key_generation()
            self.log_event("Master key pair renewed after 24 months.")

    def encrypt_content(self, content):
        """Encrypt the content using the master public key (ElGamal)."""
        h = SHA256.new(content.encode()).digest()
        k = get_random_bytes(16)  # Random bytes for encryption
        ciphertext = self.master_key.encrypt(h, k)
        encrypted_content = base64.b64encode(str(ciphertext).encode()).decode('utf-8')
        self.log_event("Encrypted content using master public key.")
        return encrypted_content

    def decrypt_content(self, encrypted_content, customer_id):
        """Decrypt content for authorized customers using the private key."""
        self.check_access(customer_id)

        private_key = self.load_private_key()
        ciphertext = eval(base64.b64decode(encrypted_content).decode())  # Be cautious with eval
        decrypted_content = private_key.decrypt(ciphertext)
        self.log_event(f"Customer {customer_id} decrypted content successfully.")
        return decrypted_content

    def grant_access(self, customer_id, content_id, duration_days):
        """Grant limited-time access to content for a customer."""
        expiry_date = datetime.now() + timedelta(days=duration_days)
        self.customers_access[customer_id] = {"content_id": content_id, "expiry": expiry_date}
        self.log_event(f"Granted access to customer {customer_id} for content {content_id} until {expiry_date}.")

    def revoke_access(self, customer_id, content_id):
        """Revoke access to content for a customer."""
        if customer_id in self.customers_access and self.customers_access[customer_id]["content_id"] == content_id:
            del self.customers_access[customer_id]
            self.log_event(f"Revoked access for customer {customer_id} for content {content_id}.")
        else:
            self.log_event(f"No access to revoke for customer {customer_id} for content {content_id}.")

    def check_access(self, customer_id):
        """Check if a customer has valid access to the content."""
        if customer_id not in self.customers_access:
            self.log_event(f"Access denied for customer {customer_id}: No access found.")
            raise Exception(f"Access denied for customer {customer_id}")
        access_details = self.customers_access[customer_id]
        if datetime.now() > access_details["expiry"]:
            self.log_event(f"Access denied for customer {customer_id}: Access expired.")
            raise Exception(f"Access denied for customer {customer_id}: Access expired.")
        self.log_event(f"Customer {customer_id} has valid access.")

    def revoke_master_key(self):
        """Revoke master private key in case of security breach."""
        if os.path.exists("master_private_key.pem"):
            os.remove("master_private_key.pem")
            self.log_event("Master private key revoked and removed due to security breach.")

    def get_logs(self):
        """Get the auditing and logs."""
        return json.dumps(self.logs, indent=2)

    def run_maintenance(self):
        """Run regular maintenance tasks, including key renewal."""
        self.renew_key_pair()
        self.log_event("Running system maintenance tasks.")

# Example Usage
if __name__ == "__main__":
    drm_system = DRMSystem()

    # Content encryption by content creators
    content = "This is a valuable e-book content."
    encrypted_content = drm_system.encrypt_content(content)

    # Grant access to a customer
    customer_id = "customer_123"
    content_id = "ebook_001"
    drm_system.grant_access(customer_id, content_id, duration_days=30)

    # Decrypt the content for the customer (valid access)
    decrypted_content = drm_system.decrypt_content(encrypted_content, customer_id)
    print(f"Decrypted content: {decrypted_content}")

    # Revoke access for the customer
    drm_system.revoke_access(customer_id, content_id)

    # Print logs (audit)
    print(drm_system.get_logs())

    # Run system maintenance (key renewal)
    drm_system.run_maintenance()
