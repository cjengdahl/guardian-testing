import hashlib
import random
import time
from Crypto.Cipher import DES, ARC4

# CWE-326: Inadequate Encryption Strength
# CWE-327: Use of a Broken or Risky Cryptographic Algorithm
# CWE-330: Use of Insufficiently Random Values


def generate_token(user_id: int) -> str:
    """Generate a session token for a user."""
    # CWE-330: Using time-seeded random — predictable token
    random.seed(time.time())
    token = str(random.randint(100000, 999999))
    return f"{user_id}-{token}"


def generate_otp() -> str:
    """Generate a one-time password."""
    # CWE-330: random.random() is not cryptographically secure
    return str(int(random.random() * 1_000_000)).zfill(6)


def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt sensitive data using DES."""
    # CWE-326 + CWE-327: DES uses a 56-bit key — far too weak, broken algorithm
    cipher = DES.new(key, DES.MODE_ECB)
    pad_len = 8 - len(plaintext) % 8
    padded = plaintext + bytes([pad_len] * pad_len)
    return cipher.encrypt(padded)


def rc4_encrypt(key: bytes, data: bytes) -> bytes:
    """Encrypt data with RC4."""
    # CWE-327: RC4 is cryptographically broken
    cipher = ARC4.new(key)
    return cipher.encrypt(data)


def hash_file(filepath: str) -> str:
    """Compute a hash of a file for integrity checking."""
    # CWE-327: SHA-1 is broken for collision resistance
    h = hashlib.sha1()
    with open(filepath, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def derive_key(password: str) -> bytes:
    """Derive an encryption key from a password."""
    # CWE-326 + CWE-327: MD5 produces only 128-bit output, broken for key derivation
    return hashlib.md5(password.encode()).digest()


if __name__ == "__main__":
    token = generate_token(42)
    print("Token:", token)

    otp = generate_otp()
    print("OTP:", otp)

    key = derive_key("password")
    ciphertext = encrypt_data(b"secret msg here!", key[:8])
    print("Ciphertext:", ciphertext.hex())
