# crypto_utils.py
import os
from typing import Optional
import base64

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

def build_session_offer_sig_bytes(sender: str, receiver: str, session_id: str, encrypted_key_b64: str) -> bytes:
    """
    Canonical bytes to sign for SESSION_OFFER authentication.
    Keep this stable across versions.
    """
    # Use a strict delimiter + UTF-8, do NOT pretty-print JSON (avoid ambiguity)
    msg = f"{sender}|{receiver}|{session_id}|{encrypted_key_b64}"
    return msg.encode("utf-8")

def rsa_sign_pss_sha256(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

def rsa_verify_pss_sha256(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

# ---------------- AES-GCM helpers ----------------

def generate_aes_key() -> bytes:
    """Generate 256-bit AES-GCM key."""
    return AESGCM.generate_key(bit_length=256)


def aes_encrypt(data_bytes: bytes, key: bytes, associated_data: Optional[bytes] = None) -> bytes:
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, data_bytes, associated_data)
    return nonce + ct

def aes_decrypt(encrypted_data: bytes, key: bytes, associated_data: Optional[bytes] = None) -> Optional[bytes]:
    if not encrypted_data or len(encrypted_data) < 13:
        return None
    nonce = encrypted_data[:12]
    ct = encrypted_data[12:]
    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, associated_data)
    except Exception:
        # treat as tampered / wrong key
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
