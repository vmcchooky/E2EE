from beanie import Document
from pydantic import Field, ConfigDict
from datetime import datetime
from beanie.odm.fields import PydanticObjectId


class Token(Document):
    """Token model for MongoDB using Beanie ODM."""

    user_id: PydanticObjectId
    refresh_token: str = Field(..., unique=True)
    expires_at: datetime
    revoked: bool = False

    class Settings:
        name = "tokens"        

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders={PydanticObjectId: str},
        populate_by_name=True,
    )
