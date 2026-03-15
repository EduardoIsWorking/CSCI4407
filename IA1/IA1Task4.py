def rot32(x, n):
    """
    Left-rotate a 32-bit integer x by n bit positions
    """
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def quarter_round(a, b, c, d):
    """
    Apply the ChaCha20 quarter-round transformation to four 32-bit words
    All additions are modulo 2^32
    If result exceeds 32 bits only the least significant 32 bits are kept
    """
    # Operation 1
    a = (a + b) & 0xFFFFFFFF   # modular addition
    d = d ^ a                  # XOR
    d = rot32(d, 16)           # left rotation by 16

    # Operation 2
    c = (c + d) & 0xFFFFFFFF
    b = b ^ c
    b = rot32(b, 12)

    # Operation block 3
    a = (a + b) & 0xFFFFFFFF
    d = d ^ a
    d = rot32(d, 8)

    # Operation block 4
    c = (c + d) & 0xFFFFFFFF
    b = b ^ c
    b = rot32(b, 7)

    return a, b, c, d

a, b, c, d = quarter_round(
    0x11111111, # a
    0x01020304, # b
    0x9b8d6f43, # c
    0x01234567) # d

e, f, g, h = quarter_round(
    0x11111101, # a
    0x01020304, # b
    0x9b8d6f43, # c
    0x01234567) # d

print(f"a = {a:032b}")
print(f"a'= {e:032b}\n")
print(f"b = {b:032b}")
print(f"b'= {f:032b}\n")
print(f"c = {c:032b}")
print(f"c'= {g:032b}\n")
print(f"d = {d:032b}")
print(f"d'= {h:032b}")