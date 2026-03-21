import hmac
import hashlib

key = b"secretkey123"
filename = "message1.txt"

with open(filename, "rb") as f:
    message = f.read()

tag = hmac.new(key, message, hashlib.sha256).hexdigest()

print("Message:", message.decode())
print("HMAC Tag:", tag)