from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import os

# Generate RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serialize private key
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Symmetric encryption (AES)
aes_key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()

plaintext = b"Secret Message"
ciphertext = encryptor.update(plaintext) + encryptor.finalize()
decrypted = decryptor.update(ciphertext) + decryptor.finalize()

# Hashing
digest = hashes.Hash(hashes.SHA256())
digest.update(b"message")
hash_value = digest.finalize()

# HMAC
h = hmac.HMAC(aes_key, hashes.SHA256())
h.update(b"auth message")
hmac_value = h.finalize()

# Verify HMAC
h2 = hmac.HMAC(aes_key, hashes.SHA256())
h2.update(b"auth message")
h2.verify(hmac_value)  # Will raise InvalidSignature if mismatch

# Digital signature
signature = private_key.sign(
    b"signed message",
    asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        salt_length=asym_padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Verify signature
public_key.verify(
    signature,
    b"signed message",
    asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        salt_length=asym_padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Key derivation using PBKDF2
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000
)
kdf_key = kdf.derive(b"password")

# Self-signed X.509 certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"mycompany.com"),
])
cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
    public_key
).serial_number(x509.random_serial_number()).not_valid_before(
    datetime.now(timezone.utc)
).not_valid_after(
    datetime.now(timezone.utc) + timedelta(days=10)
).sign(private_key, hashes.SHA256())

# Serialize certificate
cert_pem = cert.public_bytes(serialization.Encoding.PEM)

# Constant-time comparison
assert constant_time.bytes_eq(b"a" * 32, b"a" * 32)
