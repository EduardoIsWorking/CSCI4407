#!/usr/bin/env python3
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

BLOCK = 16

def pkcs7_unpad(padded: bytes) -> bytes:
    unpadder = padding.PKCS7(BLOCK * 8).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != BLOCK:
        raise ValueError("IV must be 16 bytes.")
    if len(ciphertext) % BLOCK != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes.")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return pkcs7_unpad(padded)

def main():
    
    # To demonstrate we decrypt C1.bin using iv1.bin from Step 2
    key = Path("key.bin").read_bytes()
    iv = Path("iv1.bin").read_bytes()
    ct = Path("C1.bin").read_bytes()

    recovered = aes_cbc_decrypt(key, iv, ct)
    Path("recovered.bin").write_bytes(recovered)

    print("Wrote: recovered.bin")
    print(f"recovered bytes: {len(recovered)}")

if __name__ == "__main__":
    main()
