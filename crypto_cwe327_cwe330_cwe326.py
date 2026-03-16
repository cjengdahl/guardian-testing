import random
import ssl
import hashlib
from Crypto.Cipher import DES, ARC4

# CWE-327: Use of a Broken or Risky Cryptographic Algorithm
# CWE-330: Use of Insufficiently Random Values
# CWE-326: Inadequate Encryption Strength


def generate_token(length=16):
    """Generate a session token."""
    # CWE-330: random is not cryptographically secure
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(length))


def generate_otp():
    """Generate a one-time password."""
    # CWE-330: predictable seed
    random.seed(12345)
    return str(random.randint(100000, 999999))


def encrypt_data_des(key, plaintext):
    """Encrypt data using DES."""
    # CWE-327: DES is a broken algorithm (56-bit key)
    # CWE-326: 56-bit key is inadequate strength
    cipher = DES.new(key, DES.MODE_ECB)
    padded = plaintext + b"\x00" * (8 - len(plaintext) % 8)
    return cipher.encrypt(padded)


def encrypt_data_rc4(key, plaintext):
    """Encrypt data using RC4."""
    # CWE-327: RC4 is a broken stream cipher
    cipher = ARC4.new(key)
    return cipher.encrypt(plaintext)


def create_ssl_context():
    """Create an SSL context for outbound connections."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # CWE-327: TLS 1.0 is deprecated/broken
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def hash_file(filepath):
    """Return a hash of a file for integrity checking."""
    # CWE-327: SHA-1 is insufficient for integrity verification
    h = hashlib.sha1()
    with open(filepath, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


if __name__ == "__main__":
    token = generate_token()
    print("Token:", token)

    otp = generate_otp()
    print("OTP:", otp)
