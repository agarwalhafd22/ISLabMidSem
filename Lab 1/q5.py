'''
John is reading a mystery book involving cryptography. In one part of the
book, the author gives a ciphertext "CIW" and two paragraphs later the author
tells the reader that this is a shift cipher and the plaintext is "yes". In the next
chapter, the hero found a tablet in a cave with "XVIEWYWI" engraved on it.
John immediately found the actual meaning of the ciphertext. Identify the
type of attack and plaintext.
'''

print("Encrypted Text: CIW")

eText="ciw"
dText="yes"

key=((ord(eText[0])-97)-(ord(dText[0])-97))%26

print("Key = ",key)

print("Engraved Text: XVIEWYWI")

encryptedText="xviewywi"
decryptedText=""

n=len(encryptedText)

for i in range (n):
    decryptedText = decryptedText + chr((ord(encryptedText[i]) - 97 - key) % 26 + 97)

print("Decrypted Text = "+decryptedText)