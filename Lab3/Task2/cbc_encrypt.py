#!/usr/bin/env python3
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

BLOCK = 16

def pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(BLOCK * 8).padder()
    return padder.update(data) + padder.finalize()

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    pt_padded = pkcs7_pad(plaintext)
    return enc.update(pt_padded) + enc.finalize()

def main():
    msg = Path("msg.bin").read_bytes()

    # AES key
    if Path("key.bin").exists():
        key = Path("key.bin").read_bytes()
        if len(key) != 16:
            raise ValueError("key.bin exists but is not 16 bytes.")
    else:
        key = os.urandom(16)
        Path("key.bin").write_bytes(key)

    
    # Step 2: fresh random IVs
    
    iv1 = os.urandom(16)
    iv2 = os.urandom(16)

    c1 = aes_cbc_encrypt(key, iv1, msg)
    c2 = aes_cbc_encrypt(key, iv2, msg)

    Path("iv1.bin").write_bytes(iv1)
    Path("iv2.bin").write_bytes(iv2)
    Path("C1.bin").write_bytes(c1)
    Path("C2.bin").write_bytes(c2)

    
    # Step 3: fixed IV
    
    if Path("fixed_iv.bin").exists():
        fixed_iv = Path("fixed_iv.bin").read_bytes()
        if len(fixed_iv) != 16:
            raise ValueError("fixed_iv.bin exists but is not 16 bytes.")
    else:
        fixed_iv = os.urandom(16)
        Path("fixed_iv.bin").write_bytes(fixed_iv)

    c3 = aes_cbc_encrypt(key, fixed_iv, msg)
    c4 = aes_cbc_encrypt(key, fixed_iv, msg)

    Path("C3.bin").write_bytes(c3)
    Path("C4.bin").write_bytes(c4)

    print("Wrote: key.bin, iv1.bin, iv2.bin, fixed_iv.bin, C1.bin, C2.bin, C3.bin, C4.bin")
    print(f"msg bytes: {len(msg)}")
    print(f"C1 bytes: {len(c1)}  C2 bytes: {len(c2)}  C3 bytes: {len(c3)}  C4 bytes: {len(c4)}")

if __name__ == "__main__":
    main()
