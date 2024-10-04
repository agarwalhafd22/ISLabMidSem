import hashlib
import random
from sympy import isprime


# ---- Rabin Cryptosystem for Customer Encryption ----
def rabin_keygen():
    p = q = 0
    # Ensure p and q are prime and congruent to 3 mod 4, and large enough (e.g., 512 bits)
    while not (isprime(p) and p % 4 == 3):
        p = random.getrandbits(512)
    while not (isprime(q) and q % 4 == 3):
        q = random.getrandbits(512)
    n = p * q
    return p, q, n


def rabin_encrypt(plaintext, n):
    # Convert plaintext to integer
    m = int.from_bytes(plaintext.encode(), byteorder='big')
    # Encryption: c = m^2 mod n
    c = pow(m, 2, n)
    return c


def rabin_decrypt(c, p, q):
    n = p * q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)

    # Extended Euclidean Algorithm to find yp and yq
    gcd, yp, yq = extended_gcd(p, q)

    # Four possible solutions for m
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = (yp * p * mq - yq * q * mp) % n
    r3 = n - r1
    r4 = n - r2

    # Print all four possible results
    print(f"Possible solutions: r1={r1}, r2={r2}, r3={r3}, r4={r4}")

    # Attempt to decode each solution
    for r in [r1, r2, r3, r4]:
        try:
            m_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
            decoded_message = m_bytes.decode('utf-8')
            return decoded_message
        except (ValueError, UnicodeDecodeError):
            continue

    return None  # Return None if none of the solutions can be decoded


def extended_gcd(a, b):
    """ Extended Euclidean Algorithm to find x, y where ax + by = gcd(a, b) """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t  # gcd, x, y


# ---- ElGamal Digital Signature for Customer ----
def elgamal_keygen():
    # Large prime number p
    p = 3557  # Pre-defined prime
    g = random.randint(2, p - 2)  # Generator g
    x = random.randint(2, p - 2)  # Private key x
    y = pow(g, x, p)  # Public key y
    return p, g, y, x  # Public: (p, g, y), Private: (x)


def elgamal_sign(message, p, g, x):
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    while True:
        k = random.randint(1, p - 2)  # Ensure k is valid
        if gcd(k, p - 1) == 1:  # Ensure k is coprime with p-1
            break
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)  # k^(-1) mod (p-1)
    s = (k_inv * (h - x * r)) % (p - 1)
    return r, s


def elgamal_verify(message, r, s, p, g, y):
    if not (0 < r < p):
        return False
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2


# Greatest Common Divisor
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# ---- Hashing Function ----
def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()


# ---- Menu-Driven System ----
class System:
    def __init__(self):
        self.p, self.q, self.n = rabin_keygen()  # Customer's encryption keys
        self.elgamal_p, self.elgamal_g, self.elgamal_y, self.elgamal_x = elgamal_keygen()  # ElGamal keys
        self.log_file = None  # Store log file for Auditor

    def customer_menu(self):
        print("Customer Menu")
        while True:
            print("\n1. Encrypt data")
            print("2. Hash data")
            print("3. Add digital signature")
            print("4. Exit")

            choice = input("Choose an option: ")
            if choice == '1':
                self.encrypt_data()
            elif choice == '2':
                self.hash_data()
            elif choice == '3':
                self.add_signature()
            elif choice == '4':
                break

    def encrypt_data(self):
        plaintext = input("Enter data to encrypt: ")
        self.encrypted_data = rabin_encrypt(plaintext, self.n)
        print(f"Encrypted Data: {self.encrypted_data}")

    def hash_data(self):
        plaintext = input("Enter data to hash: ")
        self.hashed_data = hash_data(plaintext)
        print(f"Hashed Data: {self.hashed_data}")

    def add_signature(self):
        if hasattr(self, 'hashed_data'):
            self.signature = elgamal_sign(self.hashed_data, self.elgamal_p, self.elgamal_g, self.elgamal_x)
            print(f"Digital Signature: {self.signature}")
        else:
            print("Please hash data first!")

    def merchant_menu(self):
        print("Merchant Menu")
        while True:
            print("\n1. Decrypt data")
            print("2. Verify digital signature")
            print("3. Convert to log file")
            print("4. Exit")

            choice = input("Choose an option: ")
            if choice == '1':
                self.decrypt_data()
            elif choice == '2':
                self.verify_signature()
            elif choice == '3':
                self.convert_to_log()
            elif choice == '4':
                break

    def decrypt_data(self):
        if hasattr(self, 'encrypted_data'):
            decrypted = rabin_decrypt(self.encrypted_data, self.p, self.q)
            self.decrypted_data = decrypted
            print(f"Decrypted Data: {decrypted}")
        else:
            print("No data to decrypt!")

    def verify_signature(self):
        if hasattr(self, 'hashed_data') and hasattr(self, 'signature'):
            valid = elgamal_verify(self.hashed_data, *self.signature, self.elgamal_p, self.elgamal_g, self.elgamal_y)
            if valid:
                print("Signature is valid!")
            else:
                print("Invalid signature!")
        else:
            print("No signature or hashed data available to verify!")

    def convert_to_log(self):
        if hasattr(self, 'decrypted_data'):
            self.log_file = f"Log File: {self.decrypted_data}"
            print("Log file created.")
        else:
            print("No data to convert to log file!")

    def auditor_menu(self):
        print("Auditor Menu")
        while True:
            print("\n1. Verify log file")
            print("2. Exit")

            choice = input("Choose an option: ")
            if choice == '1':
                self.verify_log()
            elif choice == '2':
                break

    def verify_log(self):
        if self.log_file:
            print(f"Log file verified: {self.log_file}")
        else:
            print("No log file to verify!")


# ---- Main Menu ----
def main():
    system = System()

    while True:
        print("\nMain Menu")
        print("1. Customer")
        print("2. Merchant")
        print("3. Auditor")
        print("4. Exit")

        choice = input("Choose a role: ")
        if choice == '1':
            system.customer_menu()
        elif choice == '2':
            system.merchant_menu()
        elif choice == '3':
            system.auditor_menu()
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please choose again.")


if __name__ == '__main__':
    main()

