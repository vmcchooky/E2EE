from datetime import datetime, timezone
from typing import Optional

from beanie import Document
from beanie.odm.fields import PydanticObjectId
from pydantic import ConfigDict, Field


class PublicKey(Document):
    """Public Key model for E2EE - stores user's RSA public keys (multi-device support)."""

    user_id: PydanticObjectId = Field(...,
                                      description="User who owns this key")
    public_key: str = Field(...,
                            description="Base64 encoded RSA public key (SPKI format)")
    fingerprint: str = Field(...,
                             description="SHA-256 fingerprint of the public key")
    device_id: Optional[str] = Field(
        default=None,
        description="Unique device identifier (browser fingerprint, device name, etc.)")
    device_name: Optional[str] = Field(
        default=None,
        description="Human-readable device name (e.g., 'Chrome on Windows', 'Mobile')")
    is_active: bool = Field(
        default=True,
        description="Whether this key is currently active")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "public_keys"
        indexes = [
            [("user_id", 1)],
            [("fingerprint", 1)],
            [("user_id", 1), ("device_id", 1)],  # Unique device per user
            [("user_id", 1), ("is_active", 1)],  # Active keys per user
        ]

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders={PydanticObjectId: str},
        populate_by_name=True
    )
