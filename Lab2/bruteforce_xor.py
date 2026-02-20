import sys

def read_ciphertext(filename):
    """
    # Reads the ciphertext file in binary mode ("rb").
    # Why binary mode?
    # XOR operates on raw bytes. Text mode may corrupt data via decoding/newlines.
    """
    try:
        with open(filename, "rb") as f:
            return f.read()
    except:
        """
        # Possible errors:
        # - File not found
        # - Permission denied
        # - Wrong filename/path
        """
        return None
    
def xor_with_key(data, key):
    """
    # Applies single-byte XOR to a bytes object.
    # Why this works for decryption:
    # If C = P ⊕ K, then P = C ⊕ K because XOR is its own inverse.
    #
    # data: ciphertext bytes (or plaintext bytes)
    # key: integer 0..255 (single byte)
    # returns: bytes result after XOR
    """
    try:
        return bytes([b ^ key for b in data])
    except Exception as e:
        print(f"[!] XOR error: {e}")
        return None
    
def printable_ascii_ratio(candidate):
    """
    Returns fraction of bytes that are printable ASCII (32–126 only).
    """
    if candidate is None or len(candidate) == 0:
        return 0.0

    printable_count = 0

    for b in candidate:
        if 32 <= b <= 126:
            printable_count += 1

    return printable_count / len(candidate)

def letter_space_ratio(candidate):
    """
    Returns fraction of bytes that are letters (A-Z, a-z) or spaces.
    English text is dominated by letters and spaces.
    """
    if candidate is None or len(candidate) == 0:
        return 0.0

    count = 0

    for b in candidate:
        if (65 <= b <= 90) or (97 <= b <= 122) or b == 32:
            count += 1

    return count / len(candidate)

def main():
    """
    # Validates command-line arguments using len(sys.argv).
    # Why?
    # The script needs exactly one input: the ciphertext filename.
    """
    if len(sys.argv) != 2:
        print("Usage: python3 bruteforce_xor.py <xor_chal_text.bin>")
        sys.exit(1)

    filename = sys.argv[1]
    ciphertext = read_ciphertext(filename)

    if ciphertext is None:
        print("[!] Error: Could not read the ciphertext file.")
        sys.exit(1)

    print(f"[*] Loaded ciphertext from: {filename}")
    print(f"[*] Ciphertext size: {len(ciphertext)} bytes")

    # Sanity test: XOR the first 16 bytes with an example key (0x00 keeps bytes unchanged)
    test_key = 0x00
    test_out = xor_with_key(ciphertext[:16], test_key)
    print(f"[*] Sanity test with key=0x{test_key:02x}: {test_out.hex()}")

    # Test printable ratio on ciphertext itself
    ratio = printable_ascii_ratio(ciphertext)
    print(f"[*] Printable ratio of ciphertext: {ratio:.4f}")

if __name__ == "__main__":
    main()
