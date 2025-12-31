from pydantic import BaseModel


class DeviceKeyBundle(BaseModel):
    device_id: str
    user_id: str
    identity_key: str
    signed_prekey: str
    one_time_prekey: str | None = None


class DeviceKeyResponse(BaseModel):
    device_id: str
    identity_key: str
    signed_prekey: str
    one_time_prekey: str | None = None


