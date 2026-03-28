def encrypt_file(data, pub): return data, b"key"
def decrypt_file(data, key, priv, pwd): return data
def reencrypt_aes_key(key, priv, pwd, pub): return key
def sign_file(data, priv, pwd): return "signature"
def verify_signature(data, sig, pub): return True
def hash_file_sha256(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()