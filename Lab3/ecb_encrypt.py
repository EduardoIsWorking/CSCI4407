#!/usr/bin/env python3
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16

def read_hex_key(path: str) -> bytes:
    hex_str = Path(path).read_text().strip()  # strips newline
    key = bytes.fromhex(hex_str)
    if len(key) != 16:
        raise ValueError(f"Expected 16-byte AES-128 key, got {len(key)} bytes.")
    return key

def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    if len(plaintext) % BLOCK != 0:
        raise ValueError("Plaintext length must be a multiple of 16 bytes for ECB (no padding).")
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

def main():
    key = read_hex_key("key.hex")

    p0 = Path("P0.txt").read_bytes()
    p1 = Path("P1.txt").read_bytes()

    c0 = aes_ecb_encrypt(key, p0)
    c1 = aes_ecb_encrypt(key, p1)

    Path("C0.bin").write_bytes(c0)
    Path("C1.bin").write_bytes(c1)

    print("Wrote: C0.bin (ECB(P0)), C1.bin (ECB(P1))")
    print(f"P0 bytes: {len(p0)}  P1 bytes: {len(p1)}")
    print(f"C0 bytes: {len(c0)}  C1 bytes: {len(c1)}")

if __name__ == "__main__":
    main()
