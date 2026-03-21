import hashlib

def prf(key: bytes, message: bytes) -> str:
    """Simple PRF: F_K(M) = SHA-256(K || M)"""
    combined = key + message
    tag = hashlib.sha256(combined).hexdigest()
    return tag

# Base key and messages
key = b"mysecretkey42"

messages = [
    b"Transfer 100 dollars to Bob",
    b"Transfer 500 dollars to Alice",
    b"Authorize access to server room",
]

print("=" * 60)
print("STEP 3: Tags for original messages (key = 'mysecretkey42')")
print("=" * 60)
original_tags = []
for i, msg in enumerate(messages, 1):
    tag = prf(key, msg)
    original_tags.append(tag)
    print(f"Message {i} : {msg.decode()}")
    print(f"Tag {i}     : {tag}\n")

# Step 4: Modify one message slightly
print("=" * 60)
print("STEP 4: Modify message 1 slightly, recompute tag")
print("=" * 60)
modified_msg = b"Transfer 1000 dollars to Bob"   # changed 100 -> 1000
modified_tag = prf(key, modified_msg)
print(f"Original message : {messages[0].decode()}")
print(f"Original tag     : {original_tags[0]}")
print(f"Modified message : {modified_msg.decode()}")
print(f"Modified tag     : {modified_tag}")
print(f"Tags match?      : {original_tags[0] == modified_tag}\n")

# Step 5: Change the secret key
print("=" * 60)
print("STEP 5: Same messages, different key ('newkey99')")
print("=" * 60)
new_key = b"newkey99"
for i, msg in enumerate(messages, 1):
    new_tag = prf(new_key, msg)
    print(f"Message {i} : {msg.decode()}")
    print(f"Old tag   : {original_tags[i-1]}")
    print(f"New tag   : {new_tag}")
    print(f"Tags match? : {original_tags[i-1] == new_tag}\n")



