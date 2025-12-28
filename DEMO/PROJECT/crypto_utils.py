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

def build_session_offer_sig_bytes(sender: str, receiver: str, session_id: str, encrypted_key_b64: str, ts: int) -> bytes:
    """
    Canonical bytes to sign for SESSION_OFFER authentication.
    Keep this stable across versions.
    """
    # v2 includes ts to bind offer timestamp into signature
    msg = f"{sender}|{receiver}|{session_id}|{encrypted_key_b64}|{int(ts)}|SESSION_OFFER|v2"
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
    if not isinstance(s, str) or not s:
        raise ValueError("b64d expects a non-empty base64 string")
    # validate=True: reject non-base64 characters
    return base64.b64decode(s.encode("utf-8"), validate=True)

# ---------------- AES-GCM helpers ----------------

def generate_aes_key() -> bytes:
    """Generate 256-bit AES-GCM key."""
    return AESGCM.generate_key(bit_length=256)

def aes_encrypt(data_bytes: bytes, key: bytes, associated_data: Optional[bytes] = None) -> bytes:
    if not isinstance(data_bytes, (bytes, bytearray)):
        raise TypeError("data_bytes must be bytes")
    if associated_data is not None and not isinstance(associated_data, (bytes, bytearray)):
        raise TypeError("associated_data must be bytes or None")

    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, bytes(data_bytes), bytes(associated_data) if associated_data is not None else None)
    return nonce + ct

def aes_decrypt(encrypted_data: bytes, key: bytes, associated_data: Optional[bytes] = None) -> Optional[bytes]:
    if not isinstance(encrypted_data, (bytes, bytearray)):
        return None
    if associated_data is not None and not isinstance(associated_data, (bytes, bytearray)):
        return None

    # nonce(12) + ciphertext+tag(at least 16 tag bytes)
    if len(encrypted_data) < 12 + 16:
        return None

    nonce = encrypted_data[:12]
    ct = encrypted_data[12:]
    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, bytes(associated_data) if associated_data is not None else None)
    except Exception:
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


# ---------------- Local store KDF / HKDF ----------------
import hashlib
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def kdf_scrypt(password: str, salt: bytes, length: int = 32,
               n: int = 2**14, r: int = 8, p: int = 1) -> bytes:
    """Derive a KEK from a password using scrypt."""
    if not password:
        raise ValueError("password must not be empty")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("salt invalid")
    kdf = Scrypt(salt=bytes(salt), length=int(length), n=int(n), r=int(r), p=int(p))
    return kdf.derive(password.encode("utf-8"))

def hkdf_conv_key(lsmk: bytes, username: str, peer: str, length: int = 32) -> bytes:
    """Derive per-conversation at-rest key from LSMK."""
    if not isinstance(lsmk, (bytes, bytearray)) or len(lsmk) < 16:
        raise ValueError("lsmk invalid")
    salt = hashlib.sha256(f"{username}|{peer}".encode("utf-8")).digest()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=int(length),
        salt=salt,
        info=b"SecureChatLocalStore|convkey|v1",
    )
    return hkdf.derive(bytes(lsmk))
