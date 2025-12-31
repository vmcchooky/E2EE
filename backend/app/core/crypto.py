from secrets import token_bytes


def generate_nonce(size: int = 24) -> bytes:
    """Return a cryptographically secure random nonce."""
    return token_bytes(size)


def serialize_nonce(nonce: bytes) -> str:
    """Encode a nonce for transport."""
    return nonce.hex()


