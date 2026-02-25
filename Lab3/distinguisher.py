#!/usr/bin/env python3
import secrets
from pathlib import Path
from collections import Counter
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16

def read_hex_key(path="key.hex") -> bytes:
    key_hex = Path(path).read_text().strip()
    key = bytes.fromhex(key_hex)
    if len(key) != 16:
        raise ValueError(f"Expected 16-byte AES-128 key, got {len(key)} bytes.")
    return key

def aes_ecb_encrypt(key: bytes, pt: bytes) -> bytes:
    if len(pt) % BLOCK != 0:
        raise ValueError("Plaintext length must be a multiple of 16 bytes (no padding).")
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(pt) + enc.finalize()

def split_blocks(data: bytes):
    return [data[i:i+BLOCK] for i in range(0, len(data), BLOCK)]

def has_repeated_block(ct: bytes) -> bool:
    blocks = split_blocks(ct)
    return len(set(blocks)) != len(blocks)

def distinguisher(ct: bytes) -> int:
    # b' = 0 if ciphertext shows repetition likely P0
    # b' = 1 otherwise likely P1
    return 0 if has_repeated_block(ct) else 1

def main(trials=20):
    key = read_hex_key()
    P0 = Path("P0.txt").read_bytes()
    P1 = Path("P1.txt").read_bytes()

    correct = 0
    print("trial\tb\tb'\trepeated?\tcorrect")
    for t in range(1, trials + 1):
        b = secrets.randbelow(2)  # hidden choice
        pt = P0 if b == 0 else P1
        ct = aes_ecb_encrypt(key, pt)

        bp = distinguisher(ct)
        rep = has_repeated_block(ct)
        ok = int(bp == b)
        correct += ok

        print(f"{t}\t{b}\t{bp}\t{rep}\t\t{ok}")

    pr = correct / trials
    adv = abs(pr - 0.5)
    print(f"\nPr[b' = b] = {pr:.3f}")
    print(f"Advantage |Pr[b'=b] - 1/2| = {adv:.3f}")

if __name__ == "__main__":
    main(trials=20)
