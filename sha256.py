import hashlib

def sha256Algorithm(msg):
    # Create a new SHA-256 hash object
    obj = hashlib.sha256()
    obj.update(msg.encode('utf-8'))
    hashedMsg = obj.hexdigest()

    return hashedMsg

msg = ""
hashedMsg = sha256Algorithm(msg)
