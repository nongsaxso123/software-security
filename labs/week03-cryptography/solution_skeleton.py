"""
Week 3 — FIX the misuse here. Fill in the TODOs.
pip install argon2-cffi pycryptodome
"""
import os, hashlib
from argon2 import PasswordHasher
from Crypto.Cipher import AES

ph = PasswordHasher()

def store_password(pw: str) -> str:
    # FIX: argon2id, salted automatically
    return ph.hash(pw)

def verify_password(hash_: str, pw: str) -> bool:
    try:
        return ph.verify(hash_, pw)
    except Exception:
        return False

def is_legacy_md5(hash_: str) -> bool:
    # a raw MD5 hex digest is always exactly 32 hex characters; argon2id's
    # own hash strings start with "$argon2id$" and are much longer
    return len(hash_) == 32 and all(c in "0123456789abcdef" for c in hash_)

def verify_and_migrate(hash_: str, pw: str) -> tuple[bool, str | None]:
    """Verify a login. If the stored hash is still legacy MD5 and the
    password is correct, return a fresh argon2id hash to overwrite it with —
    this is the only moment we ever see the plaintext, so it's the only
    moment we can upgrade the record."""
    if is_legacy_md5(hash_):
        if hashlib.md5(pw.encode()).hexdigest() == hash_:
            return True, store_password(pw)  # migrate to argon2id now
        return False, None
    return verify_password(hash_, pw), None

def encrypt_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    # FIX: authenticated encryption (AES-GCM), random nonce, key from env/KMS
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce, ct, tag

def decrypt_gcm(nonce: bytes, ct: bytes, tag: bytes, key: bytes) -> bytes:
    # raises ValueError if the tag doesn't match -- tampering is detected here
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def reset_token() -> str:
    # FIX: CSPRNG
    import secrets
    return secrets.token_urlsafe(16)

if __name__ == "__main__":
    key = bytes.fromhex(os.environ.get("ENC_KEY_HEX", os.urandom(32).hex()))
    h = store_password("password123")
    print("argon2 ok:", verify_password(h, "password123"))
    print("gcm:", encrypt_gcm(b"secret", key))
    print("token:", reset_token())

    # demo: a legacy MD5 record logging in and getting migrated to argon2id
    legacy_hash = hashlib.md5(b"password123").hexdigest()
    ok, new_hash = verify_and_migrate(legacy_hash, "password123")
    print("legacy login ok:", ok, "| migrated to argon2id:", new_hash is not None)

    # demo: AES-GCM round trip, then prove a tampered ciphertext fails to decrypt
    nonce, ct, tag = encrypt_gcm(b"secret", key)
    print("round-trip ok:", decrypt_gcm(nonce, ct, tag, key) == b"secret")
    tampered_ct = bytes([ct[0] ^ 0x01]) + ct[1:]  # flip one bit of the first byte
    try:
        decrypt_gcm(nonce, tampered_ct, tag, key)
        print("tampered decrypt: DID NOT FAIL (bug!)")
    except ValueError as e:
        print("tampered decrypt failed as expected:", e)
