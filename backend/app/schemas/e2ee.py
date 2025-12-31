"""Schemas for E2EE (End-to-End Encryption) API."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class PublicKeyRegister(BaseModel):
    """Request to register/update user's public key (multi-device support)."""
    public_key: str = Field(...,
                            description="Base64 encoded RSA public key (SPKI format)")
    fingerprint: str = Field(...,
                             description="SHA-256 fingerprint of the public key")
    device_id: Optional[str] = Field(
        default=None,
        description="Unique device identifier (optional, auto-generated if not provided)")
    device_name: Optional[str] = Field(
        default=None,
        description="Human-readable device name (optional)")


class PublicKeyResponse(BaseModel):
    """Response containing a user's public key."""
    user_id: str
    username: str
    display_name: Optional[str] = None
    public_key: str
    fingerprint: str
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    is_active: bool = True
    updated_at: datetime


class SessionKeyExchange(BaseModel):
    """Request to exchange session key with another user (direct or group)."""
    recipient_id: str = Field(..., description="User ID of the recipient")
    encrypted_session_key: str = Field(
        ..., description="Base64 encoded encrypted AES session key")
    target_device_id: Optional[str] = Field(
        None, description="Optional device ID to target a specific recipient device")
    conversation_id: Optional[str] = Field(
        None, description="Optional conversation ID - if provided, indicates this is a group session key")
    key_version: Optional[int] = Field(
        None, description="Key version for group session keys (required for group keys)")
    signature: str = Field(
        ..., description="Base64 encoded RSA-PSS signature of the payload")
    timestamp: int = Field(
        ..., description="Unix timestamp of when the key was signed")


class PendingKeyEnvelope(BaseModel):
    """Pending session/group key envelope for offline delivery."""
    id: str
    conversation_id: Optional[str] = None
    recipient_user_id: str
    recipient_device_id: Optional[str] = None
    key_version: Optional[int] = None
    encrypted_session_key: str
    sender_user_id: str
    signature: str
    timestamp: int
    created_at: datetime


class PendingKeyAck(BaseModel):
    """Ack payload to mark pending keys as delivered."""
    ids: list[str] = Field(..., min_items=1)


class EncryptedMessage(BaseModel):
    """Encrypted message payload."""
    recipient_id: str = Field(..., description="User ID of the recipient")
    conversation_id: Optional[str] = Field(
        None, description="Conversation ID if exists")
    ciphertext: str = Field(...,
                            description="Base64 encoded encrypted message (AES-GCM)")
    is_e2ee: bool = Field(True, description="Flag indicating E2EE message")


class UserPublicKeyInfo(BaseModel):
    """Basic public key info for a user."""
    user_id: str
    username: str
    display_name: Optional[str] = None
    fingerprint: str
    has_public_key: bool = True
