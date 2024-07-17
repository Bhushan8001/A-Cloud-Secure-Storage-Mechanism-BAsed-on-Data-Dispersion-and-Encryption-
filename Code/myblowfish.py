from Crypto.Cipher import Blowfish
from Crypto import Random
import base64

# Encryption
def encrypt_string(key, plaintext):
    iv = Random.new().read(Blowfish.block_size)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    plaintext = plaintext.encode('utf-8')
    padding_length = Blowfish.block_size - len(plaintext) % Blowfish.block_size
    padding = bytes([padding_length]) * padding_length
    plaintext += padding
    ciphertext = iv + cipher.encrypt(plaintext)
    return base64.b64encode(ciphertext).decode('utf-8')

# Decryption
def decrypt_string(key, ciphertext):
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    iv = ciphertext[:Blowfish.block_size]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[Blowfish.block_size:])
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]
    return plaintext.decode('utf-8')