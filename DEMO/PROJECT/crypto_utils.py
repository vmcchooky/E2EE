# crypto_utils.py
import os
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------- RSA helpers ----------------

def load_public_key_from_bytes(key_bytes: bytes):
    """Load RSA public key object from PEM bytes."""
    return serialization.load_pem_public_key(key_bytes, backend=default_backend())


def rsa_encrypt(data: bytes, public_key_obj) -> bytes:
    """Encrypt bytes with RSA-OAEP(SHA-256)."""
    return public_key_obj.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(encrypted_data: bytes, private_key_obj) -> bytes:
    """Decrypt bytes with RSA-OAEP(SHA-256)."""
    return private_key_obj.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------- AES-GCM helpers ----------------

def generate_aes_key() -> bytes:
    """Generate 256-bit AES-GCM key."""
    return AESGCM.generate_key(bit_length=256)


def aes_encrypt(data_bytes: bytes, key: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    AES-GCM encrypt.
    Returns: nonce(12) + ciphertext||tag
    """
    if not isinstance(data_bytes, (bytes, bytearray)):
        raise TypeError("data_bytes must be bytes")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")

    aesgcm = AESGCM(bytes(key))
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, bytes(data_bytes), associated_data=associated_data)
    return nonce + ct


def aes_decrypt(encrypted_data: bytes, key: bytes, associated_data: Optional[bytes] = None) -> Optional[bytes]:
    """
    AES-GCM decrypt.
    Input: nonce(12) + ciphertext||tag
    Returns plaintext bytes, or None if authentication fails.
    """
    try:
        if not isinstance(encrypted_data, (bytes, bytearray)):
            raise TypeError("encrypted_data must be bytes")
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes")

        buf = bytes(encrypted_data)
        nonce = buf[:12]
        ct = buf[12:]
        aesgcm = AESGCM(bytes(key))
        return aesgcm.decrypt(nonce, ct, associated_data=associated_data)
    except Exception:
        # InvalidTag or malformed input -> treat as tamper / wrong key
        return None


# ---------------- Key storage ----------------

def generate_or_load_keys(name: str, password: str):
    """Create or load RSA keypair protected by password."""
    os.makedirs("Keys/Private", exist_ok=True)
    os.makedirs("Keys/Public", exist_ok=True)

    private_key_file = f"Keys/Private/private_key_{name}.pem"
    public_key_file = f"Keys/Public/public_key_{name}.pem"

    if not password:
        print("Loi: password bao ve private key khong duoc rong.")
        return None, None

    try:
        if os.path.exists(private_key_file):
            with open(private_key_file, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode("utf-8"),
                    backend=default_backend(),
                )
            with open(public_key_file, "rb") as f:
                public_key_bytes = f.read()
                serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
            return private_key, public_key_bytes

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        with open(private_key_file, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
                )
            )

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(public_key_file, "wb") as f:
            f.write(public_key_bytes)

        return private_key, public_key_bytes

    except Exception as e:  # noqa: BLE001
        print(f"Loi khi xu ly khoa (co the do sai password): {e}")
        return None, None


def public_key_fingerprint(pubkey_bytes: bytes, length: int = 32) -> str:
    """SHA-256 fingerprint (hex) truncated to `length` chars."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(pubkey_bytes)
    return digest.finalize().hex()[:length]


def session_confirm_token(aes_key: bytes, session_id: str, length: int = 32) -> str:
    """Deterministic token for SESSION_ACK verification."""
    if not isinstance(aes_key, (bytes, bytearray)):
        raise TypeError("aes_key must be bytes")
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("session_id must be a non-empty string")

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(bytes(aes_key))
    digest.update(session_id.encode("utf-8"))
    digest.update(b"|SESSION_ACK|v1")
    return digest.finalize().hex()[:length]
