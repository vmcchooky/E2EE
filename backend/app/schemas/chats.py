from pydantic import BaseModel, Field, model_validator


class ConversationCreate(BaseModel):
    title: str | None = None
    participant_ids: list[str] = Field(
        default_factory=list, alias="participant_ids")
    participantIds: list[str] | None = None
    memberIds: list[str] | None = None
    model_config = {
        "populate_by_name": True,
        "extra": "ignore",
    }

    @model_validator(mode="after")
    def normalize_ids(self):
        ids = self.participant_ids or self.participantIds or self.memberIds or []
        self.participant_ids = ids
        return self


class AddMembersRequest(BaseModel):
    member_ids: list[str] = Field(..., min_items=1,
                                  description="Danh sách user IDs để thêm vào group")


class InviteLinkResponse(BaseModel):
    invite_code: str
    invite_url: str
    expires_at: str | None = None


class JoinGroupRequest(BaseModel):
    invite_code: str = Field(..., description="Mã invite để join group")


class ConversationResponse(BaseModel):
    id: str
    title: str | None = None


class MessagePayload(BaseModel):
    content: str


class DirectMessagePayload(MessagePayload):
    recipient_id: str
    member_ids: list[str] | None = None
    conversation_id: str | None = None
    # Counter for anti-replay protection (E2EE direct messages only)
    counter: int | None = Field(
        default=None, description="Message counter for anti-replay protection")


class GroupMessagePayload(MessagePayload):
    conversation_id: str
    # Version của group session key dùng để mã hóa message này (None = không E2EE)
    key_version: int | None = None
