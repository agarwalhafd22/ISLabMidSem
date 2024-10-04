'''
Encrypt the message "the house is being sold tonight" using each of the
following ciphers. Ignore the space between words. Decrypt the message to
get the original plaintext:
a) Vigenere cipher with key: "dollars"
b) Autokey cipher with key = 7
'''


("Enter a text:")
plainText = input().lower()
n = len(plainText)
plainTextAS = ""

print("\nPlain text: " + plainText)

# Remove spaces from the plain text
for i in range(n):
    if plainText[i] != " ":
        plainTextAS = plainTextAS + plainText[i]

n2 = len(plainTextAS)

# Vigenère Cipher

key = "dollars"
keyNew = ""
c = 0
i = 0
while i < n2:
    if c == len(key):
        c = 0
    keyNew = keyNew + key[c]
    c = c + 1
    i = i + 1

cipherVigenere = ""
decryptedVigenere = ""

# Encryption for Vigenère Cipher
for i in range(n2):
    cipherVigenere = cipherVigenere + chr((((ord(plainTextAS[i]) - 97 + ord(keyNew[i]) - 97) % 26) + 97))
print("\nVigenere Cipher Text = " + cipherVigenere)

# Decryption for Vigenère Cipher
for i in range(n2):
    decryptedVigenere = decryptedVigenere + chr((((ord(cipherVigenere[i]) - 97 - (ord(keyNew[i]) - 97)) % 26) + 97))
print("Vigenere Decrypted Text = " + decryptedVigenere)

# Autokey Cipher

autoKey = 7
cipherAutoKey = ""
cipherAutoKeyInter = ""

# First character of the key
cipherAutoKeyInter = cipherAutoKeyInter + chr(autoKey + 97)

# Append rest of the plaintext for autokey intermediate
for i in range(n2 - 1):
    cipherAutoKeyInter = cipherAutoKeyInter + plainTextAS[i]

# Encryption for Autokey Cipher
for i in range(n2):
    cipherAutoKey = cipherAutoKey + chr(((ord(plainTextAS[i]) - 97 + ord(cipherAutoKeyInter[i]) - 97) % 26) + 97)

print("\nAutokey Cipher Text = " + cipherAutoKey)

# Decryption for Autokey Cipher
decryptedAutoKey = ""

# First decrypted character
decryptedAutoKey = decryptedAutoKey + chr(((ord(cipherAutoKey[0]) - 97 - autoKey) % 26) + 97)

# Decrypt the remaining characters using the previously decrypted character
for i in range(1, n2):
    decryptedAutoKey = decryptedAutoKey + chr(((ord(cipherAutoKey[i]) - 97 - (ord(decryptedAutoKey[i - 1]) - 97)) % 26) + 97)

print("Autokey Decrypted Text = " + decryptedAutoKey)
