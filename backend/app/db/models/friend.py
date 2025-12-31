from datetime import datetime
from typing import Any

from beanie import Document
from beanie.odm.fields import PydanticObjectId
from pydantic import ConfigDict, Field, model_validator
from pymongo import IndexModel


class Friend(Document):
    """Friend model for MongoDB using Beanie ODM."""
    
    userA: PydanticObjectId = Field(..., description="User A (luôn nhỏ hơn userB)")
    userB: PydanticObjectId = Field(..., description="User B (luôn lớn hơn userA)")
    timestamps: datetime = Field(default_factory=datetime.now)

    @model_validator(mode='before')
    @classmethod
    def normalize_users(cls, data: Any) -> Any:
        """Chuẩn hóa thứ tự userA và userB: userA luôn < userB."""
        if isinstance(data, dict):
            userA = data.get('userA') or data.get('user_a')
            userB = data.get('userB') or data.get('user_b')
            
            if userA and userB:
                if isinstance(userA, str):
                    userA = PydanticObjectId(userA)
                if isinstance(userB, str):
                    userB = PydanticObjectId(userB)
                
                if userA > userB:
                    data['userA'], data['userB'] = userB, userA
                else:
                    data['userA'], data['userB'] = userA, userB
        
        return data

    class Settings:
        name = "friends"
        indexes = [
            IndexModel([("userA", 1), ("userB", 1)], unique=True, name="unique_friendship"),
            IndexModel([("userA", 1)], name="userA_idx"),
            IndexModel([("userB", 1)], name="userB_idx"),
            IndexModel([("timestamps", -1)], name="timestamps_idx"),
        ]

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders={PydanticObjectId: str},
        populate_by_name=True
    )