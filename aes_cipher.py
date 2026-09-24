import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-256 uses a 32-byte key.
key = AESGCM.generate_key(bit_length=256)

# AES-GCM uses a fresh 12-byte nonce for every encryption.
nonce = os.urandom(12)

# Plaintext message.
plaintext = b"Hello, this is our AES project."

# Create AES-GCM object and encrypt the plaintext.
aes_gcm = AESGCM(key)
ciphertext = aes_gcm.encrypt(nonce, plaintext, None)

# Decrypt with the same key and nonce.
decrypted = aes_gcm.decrypt(nonce, ciphertext, None)

print("AES mode: AES-256-GCM")
print("Key size: 256 bits")
print("Plaintext:", plaintext.decode())
print("Ciphertext (hex):", ciphertext.hex())
print("Decrypted:", decrypted.decode())
print("Result:", "PASS" if decrypted == plaintext else "FAIL")