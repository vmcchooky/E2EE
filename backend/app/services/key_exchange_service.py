from app.schemas.keys import DeviceKeyBundle, DeviceKeyResponse


class KeyExchangeService:
    """Service for managing device key exchange. TODO: Implement with Beanie."""

    async def publish_device_keys(self, bundle: DeviceKeyBundle) -> DeviceKeyResponse:
        # TODO: persist bundle in database with Beanie
        return DeviceKeyResponse(**bundle.model_dump())

    async def fetch_device_keys(self, device_id: str) -> DeviceKeyResponse:
        # TODO: fetch from persistence layer with Beanie
        return DeviceKeyResponse(
            device_id=device_id,
            identity_key="pending",
            signed_prekey="pending",
            one_time_prekey=None,
        )


