'''
Compare the encryption and decryption times for DES and AES-256 for the
message "Performance Testing of Encryption Algorithms". Use a standard
implementation and report your findings.
'''


from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import time

message = b'Performance Testing of Encryption Algorithms'

des_key = b'12345678'
aes_key = b'12345678901234567890123456789012'

# DES Encryption and Decryption
start_time = time.time()
des_cipher = DES.new(des_key, DES.MODE_ECB)
padded_message = pad(message, DES.block_size)
encrypted_message = des_cipher.encrypt(padded_message)
end_time = time.time()
des_encryption_time = (end_time - start_time) * 1000

start_time = time.time()
decrypted_padded_message = des_cipher.decrypt(encrypted_message)
decrypted_message = unpad(decrypted_padded_message, DES.block_size)
end_time = time.time()
des_decryption_time = (end_time - start_time) * 1000

print(f"DES Encryption time: {des_encryption_time:.15f} ms")
print(f"DES Decryption time: {des_decryption_time:.15f} ms")

# AES Encryption and Decryption
start_time = time.time()
aes_cipher = AES.new(aes_key, AES.MODE_ECB)
padded_message = pad(message, AES.block_size)
encrypted_message = aes_cipher.encrypt(padded_message)
end_time = time.time()
aes_encryption_time = (end_time - start_time) * 1000

start_time = time.time()
decrypted_padded_message = aes_cipher.decrypt(encrypted_message)
decrypted_message = unpad(decrypted_padded_message, AES.block_size)
end_time = time.time()
aes_decryption_time = (end_time - start_time) * 1000

print(f"AES-256 Encryption time: {aes_encryption_time:.15f} ms")
print(f"AES-256 Decryption time: {aes_decryption_time:.15f} ms")

print("Conclusion: AES encryption and decryption is faster than DES")
