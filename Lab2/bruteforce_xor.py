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
    except Exception as e:
        """
        # Possible errors:
        # - File not found
        # - Permission denied
        # - Wrong filename/path
        """
        print(f"[!] Could not open '{filename}': {e}")
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

def common_word_score(candidate):
    """
    Counts occurrences of very common English words.
    More occurrences => more likely valid English plaintext.
    """
    if candidate is None or len(candidate) == 0:
        return 0

    lower = candidate.lower()

    common_words = [
        b" the ",
        b" and ",
        b" is ",
        b" to ",
        b" of ",
        b" in ",
        b" security ",
        b" xor "
    ]

    word_count = 0

    for word in common_words:
        word_count += lower.count(word)

    return word_count

def score_candidate(candidate):
    """
    Scores a candidate plaintext by how close its statistics are to expected English.
    Uses:
      - printable_ascii_ratio: target ~ 0.98
      - letter_space_ratio: target ~ 0.85 (midpoint of 0.80-0.90)

    Higher score = closer to expected English-like ratios.
    """

    pr = printable_ascii_ratio(candidate)
    lsr = letter_space_ratio(candidate)

    # Targets based on typical English text characteristics (with punctuation allowed)
    target_pr = 0.98
    target_lsr = 0.85

    # Distance from targets (smaller is better)
    dist_pr = abs(pr - target_pr)
    dist_lsr = abs(lsr - target_lsr)

    # Weighted distance
    weighted_distance = (1.0 * dist_pr) + (2.0 * dist_lsr)

    # Convert distance to positive closeness score
    score = 1.0 - weighted_distance

    # The closer to 1 the score is the better
    return score

def brute_force_xor(ciphertext):
    """
    Tries all keys 0x00..0xFF, decrypts with each key, computes score, and sorts.
    Returns a list of tuples: (score, key, candidate_plaintext) sorted best->worst.
    """
    results = []

    for key in range(256):
        candidate = xor_with_key(ciphertext, key)
        s = score_candidate(candidate)
        results.append((s, key, candidate))

    results.sort(reverse=True, key=lambda x: x[0])
    return results
    

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

    '''
    The following was used during development to verify that the XOR function and scoring metrics work as expected.
    I commented it out as it is not needed for the final script but worth keeping for reference and showing 
    the thought process during development of the tool.
    '''

    # Sanity test: XOR the first 16 bytes with an example key (0x00 keeps bytes unchanged)
    # test_key = 0x00
    # test_out = xor_with_key(ciphertext[:16], test_key)
    # print(f"[*] Sanity test with key=0x{test_key:02x}: {test_out.hex()}")

    # # Ciphertext tests
    # print("\n--- Ciphertext Metrics ---")

    # # Test printable ratio on ciphertext itself
    # ratio = printable_ascii_ratio(ciphertext)
    # print(f"[*] Printable ratio of ciphertext: {ratio:.4f}")

    # # Test letter_space_ratio on ciphertext
    # cipher_ratio = letter_space_ratio(ciphertext)
    # print(f"[*] Letter+Space ratio of ciphertext: {cipher_ratio:.4f}")

    # # Test common_word_score on ciphertext
    # cipher_word_score = common_word_score(ciphertext)
    # print(f"[*] Common word score of ciphertext: {cipher_word_score}")

    # # English test sentence
    # test_sentence = b"This is the security lab and the xor exercise."

    # print("\n--- English Test Sentence Metrics ---")

    # print(f"[*] Printable ratio: {printable_ascii_ratio(test_sentence):.4f}")
    # print(f"[*] Letter+Space ratio: {letter_space_ratio(test_sentence):.4f}")
    # print(f"[*] Common word score: {common_word_score(test_sentence)}")

    # Brute-force XOR decryption Scoring
    results = brute_force_xor(ciphertext)

    print("\n--- Top 3 candidate keys by Combination Scoring Rule ---")
    for i in range(3):
        s, key, candidate = results[i]
        preview = candidate[:120].decode(errors="replace")
        pr = printable_ascii_ratio(candidate)
        lsr = letter_space_ratio(candidate)
        print(f"{i+1}) Key: 0x{key:02x} | Score: {s:.6f} | printable={pr:.4f} | letter+space={lsr:.4f}")
        print(f"   Preview: {preview}\n")

    # Recover and save the best plaintext
    best_score, best_key, best_plaintext = results[0]

    print(f"[+] Selected best key: 0x{best_key:02x} (score={best_score:.6f})")

    output_filename = "recovered_text.txt"
    with open(output_filename, "wb") as out:
        out.write(best_plaintext)

    print(f"[+] Saved decrypted plaintext to: {output_filename}")

    # Quick verification metrics on recovered plaintext
    pr_best = printable_ascii_ratio(best_plaintext)
    lsr_best = letter_space_ratio(best_plaintext)

    print("\n--- Verification Metrics (Recovered Plaintext) ---")
    print(f"[*] Printable ratio: {pr_best:.4f}")
    print(f"[*] Letter+Space ratio: {lsr_best:.4f}")

if __name__ == "__main__":
    main()
