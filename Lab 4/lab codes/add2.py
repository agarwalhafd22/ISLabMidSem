from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


class VulnerableRSA:
    def __init__(self, bits=512):
        # Generate weak RSA key pair
        self.p = number.getPrime(bits // 2)  # p should be larger
        self.q = number.getPrime(bits // 2)  # q should be larger
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = 65537  # Common choice for e
        self.d = number.inverse(self.e, self.phi)

    def encrypt(self, message):
        rsa_key = RSA.construct((self.n, self.e))
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.encrypt(message)

    def decrypt(self, ciphertext):
        rsa_key = RSA.construct((self.n, self.e, self.d))
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.decrypt(ciphertext)

    def recover_private_key(self):
        # Attempt to factor n to retrieve p and q
        # This is the attack
        for i in range(2, int(self.n ** 0.5) + 1):
            if self.n % i == 0:
                q = self.n // i
                p = i
                if p > 1 and q > 1:
                    return p, q, number.inverse(self.e, (p - 1) * (q - 1))

        return None, None, None


if __name__ == "__main__":
    # Create vulnerable RSA instance
    rsa = VulnerableRSA()

    # Original message
    message = b"Sensitive information"
    print(f"Original message: {message}")

    # Encrypt the message
    ciphertext = rsa.encrypt(message)
    print(f"Ciphertext: {ciphertext}")

    # Recover the private key by factoring n
    p, q, d = rsa.recover_private_key()

    if d:
        print(f"Recovered p: {p}, q: {q}, d: {d}")

        # Decrypt the message using the recovered private key
        rsa_key = RSA.construct((rsa.n, rsa.e, d))
        cipher = PKCS1_OAEP.new(rsa_key)
        decrypted_message = cipher.decrypt(ciphertext)
        print(f"Decrypted message: {decrypted_message}")
    else:
        print("Failed to recover private key.")
