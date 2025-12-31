"""API endpoints for E2EE (End-to-End Encryption)."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from bson import ObjectId
from bson.errors import InvalidId
from datetime import datetime, timezone
from logging import getLogger

from app.dependencies.auth import get_current_user
from app.db.models import User
from app.db.models.public_key import PublicKey
from app.db.models.pending_key import PendingSessionKey
from app.schemas.e2ee import (
    PublicKeyRegister,
    PublicKeyResponse,
    SessionKeyExchange,
    UserPublicKeyInfo,
    PendingKeyEnvelope,
    PendingKeyAck,
)
from app.schemas.response import BaseResponse
from app.ws.connection_manager import manager

logger = getLogger("uvicorn.error")

router = APIRouter()


@router.post(
    "/keys/register",
    response_model=BaseResponse[dict],
    status_code=status.HTTP_200_OK,
)
async def register_public_key(
    payload: PublicKeyRegister,
    current_user: User = Depends(get_current_user),
) -> BaseResponse[dict]:
    """Register or update the current user's public key (multi-device support)."""
    try:
        user_id = current_user.id

        # Generate device_id if not provided (use fingerprint as fallback)
        # Use first 16 chars of fingerprint
        device_id = payload.device_id or payload.fingerprint[:16]

        # Check if this device already has a public key
        existing = await PublicKey.find_one(
            PublicKey.user_id == user_id,
            PublicKey.device_id == device_id
        )

        if existing:
            # Update existing key for this device
            existing.public_key = payload.public_key
            existing.fingerprint = payload.fingerprint
            existing.device_name = payload.device_name or existing.device_name
            existing.is_active = True
            existing.updated_at = datetime.now(timezone.utc)
            await existing.save()
            message = "Public key updated successfully for this device"
        else:
            # Create new key for this device
            public_key = PublicKey(
                user_id=user_id,
                public_key=payload.public_key,
                fingerprint=payload.fingerprint,
                device_id=device_id,
                device_name=payload.device_name,
                is_active=True,
            )
            await public_key.insert()
            message = "Public key registered successfully for this device"

        return BaseResponse(
            status_code=status.HTTP_200_OK,
            success=True,
            message=message,
            data={
                "user_id": str(user_id),
                "device_id": device_id,
                "fingerprint": payload.fingerprint,
            },
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to register public key: {str(e)}",
        )


@router.get(
    "/keys/me",
    response_model=BaseResponse[PublicKeyResponse | None],
    status_code=status.HTTP_200_OK,
)
async def get_my_public_key(
    current_user: User = Depends(get_current_user),
) -> BaseResponse:
    """Get the current user's public key."""
    try:
        public_key = await PublicKey.find_one(PublicKey.user_id == current_user.id)

        if not public_key:
            return BaseResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                message="No public key registered",
                data=None,
            )

        return BaseResponse(
            status_code=status.HTTP_200_OK,
            success=True,
            message="Public key retrieved",
            data=PublicKeyResponse(
                user_id=str(current_user.id),
                username=current_user.username,
                display_name=current_user.display_name,
                public_key=public_key.public_key,
                fingerprint=public_key.fingerprint,
                updated_at=public_key.updated_at,
            ),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get public key: {str(e)}",
        )


@router.get(
    "/keys/{user_id}",
    response_model=BaseResponse[List[PublicKeyResponse]],
    status_code=status.HTTP_200_OK,
)
async def get_user_public_keys(
    user_id: str,
    device_id: Optional[str] = None,
    _current_user: User = Depends(get_current_user),
) -> BaseResponse:
    """Get another user's public keys by user ID (multi-device support).

    If device_id is provided, returns only that device's key.
    Otherwise, returns all active keys for the user.
    """
    try:
        target_user_id = ObjectId(user_id)
    except (InvalidId, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format",
        )

    try:
        # Get user info
        user = await User.get(target_user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        # Get public keys (filter by device_id if provided, otherwise get all active keys)
        if device_id:
            public_keys = await PublicKey.find(
                PublicKey.user_id == target_user_id,
                PublicKey.device_id == device_id,
                PublicKey.is_active == True
            ).to_list()
        else:
            # Get all active keys for multi-device support
            public_keys = await PublicKey.find(
                PublicKey.user_id == target_user_id,
                PublicKey.is_active == True
            ).to_list()

        if not public_keys:
            return BaseResponse(
                status_code=status.HTTP_200_OK,
                success=True,
                message="User has no public key registered",
                data=[],
            )

        # Convert to response format
        keys_data = [
            PublicKeyResponse(
                user_id=str(user.id),
                username=user.username,
                display_name=user.display_name,
                public_key=key.public_key,
                fingerprint=key.fingerprint,
                device_id=key.device_id,
                device_name=key.device_name,
                is_active=key.is_active,
                updated_at=key.updated_at,
            )
            for key in public_keys
        ]

        return BaseResponse(
            status_code=status.HTTP_200_OK,
            success=True,
            message="Public keys retrieved",
            data=keys_data,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get public keys: {str(e)}",
        )


@router.get(
    "/keys/conversation/{conversation_id}",
    response_model=BaseResponse[List[UserPublicKeyInfo]],
    status_code=status.HTTP_200_OK,
)
async def get_conversation_public_keys(
    conversation_id: str,
    current_user: User = Depends(get_current_user),
) -> BaseResponse:
    """Get public keys of all participants in a conversation."""
    from app.db.models.conversation import Conversation

    try:
        conv_id = ObjectId(conversation_id)
    except (InvalidId, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid conversation ID format",
        )

    try:
        # Get conversation
        conversation = await Conversation.get(conv_id)
        if not conversation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Conversation not found",
            )

        # Check if current user is participant
        participant_ids = [p.user_id for p in conversation.participants]
        if current_user.id not in participant_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not a participant of this conversation",
            )

        # Get all participants' public keys (except current user)
        result: List[UserPublicKeyInfo] = []

        for participant in conversation.participants:
            if participant.user_id == current_user.id:
                continue  # Skip self

            user = await User.get(participant.user_id)
            if not user:
                continue

            public_key = await PublicKey.find_one(PublicKey.user_id == participant.user_id)

            result.append(
                UserPublicKeyInfo(
                    user_id=str(user.id),
                    username=user.username,
                    display_name=user.display_name,
                    fingerprint=public_key.fingerprint if public_key else "",
                    has_public_key=public_key is not None,
                )
            )

        return BaseResponse(
            status_code=status.HTTP_200_OK,
            success=True,
            message="Public keys retrieved",
            data=result,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get public keys: {str(e)}",
        )


@router.post(
    "/session/exchange",
    response_model=BaseResponse[dict],
    status_code=status.HTTP_200_OK,
)
async def exchange_session_key(
    payload: SessionKeyExchange,
    current_user: User = Depends(get_current_user),
) -> BaseResponse:
    """Send encrypted session key to another user via WebSocket (multi-device support).

    If recipient has multiple devices, the session key will be sent to all active devices.
    """
    try:
        recipient_id = ObjectId(payload.recipient_id)
    except (InvalidId, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid recipient ID format",
        )

    try:
        # If this is a group key exchange (conversation_id provided), check if user is the group owner
        if payload.conversation_id:
            from app.db.models.conversation import Conversation
            try:
                conv_id = ObjectId(payload.conversation_id)
                conversation = await Conversation.get(conv_id)
                if not conversation:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Conversation not found",
                    )

                # Check if it's a group conversation
                if conversation.type != "group":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Conversation is not a group",
                    )

                # Check if current user is the group owner
                if not conversation.group or not conversation.group.created_by:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid group",
                    )

                if conversation.group.created_by != current_user.id:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Chỉ chủ nhóm mới có thể re-key nhóm",
                    )
            except (InvalidId, TypeError):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid conversation ID format",
                )

        # Verify recipient exists
        recipient = await User.get(recipient_id)
        if not recipient:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recipient not found",
            )

        # Get all active public keys for recipient (multi-device)
        recipient_keys = await PublicKey.find(
            PublicKey.user_id == recipient_id,
            PublicKey.is_active == True
        ).to_list()

        if not recipient_keys:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recipient has no active public keys",
            )

        # Send session key to recipient's devices via WebSocket
        # If target_device_id is specified, only send to that device
        # Otherwise, send to all active devices (but each device needs its own encrypted key)
        sent_count = 0

        # Filter devices based on target_device_id
        target_devices = recipient_keys
        if payload.target_device_id:
            target_devices = [
                k for k in recipient_keys if k.device_id == payload.target_device_id]

        if not target_devices:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target device not found or inactive",
            )

        for key in target_devices:
            try:
                sent = await manager.send_to_user(
                    str(recipient_id),
                    "session-key-exchange",
                    {
                        "senderId": str(current_user.id),
                        "senderUsername": current_user.username,
                        "senderDisplayName": current_user.display_name,
                        "encryptedSessionKey": payload.encrypted_session_key,
                        # Sender's device ID (for reference)
                        "deviceId": key.device_id,
                        # Recipient's device ID (this key is for this device)
                        "recipientDeviceId": key.device_id,
                        # Conversation ID (if provided, indicates group key)
                        "conversationId": payload.conversation_id,
                        # Key version (for group keys, identifies which version this is)
                        "keyVersion": payload.key_version,
                        # Security fields
                        "signature": payload.signature,
                        "timestamp": payload.timestamp,
                    },
                )
                if sent:
                    sent_count += 1
                else:
                    # Store pending if user/device is offline
                    pending = PendingSessionKey(
                        conversation_id=ObjectId(payload.conversation_id)
                        if payload.conversation_id
                        else None,
                        recipient_user_id=recipient_id,
                        recipient_device_id=key.device_id,
                        key_version=payload.key_version,
                        encrypted_session_key=payload.encrypted_session_key,
                        sender_user_id=current_user.id,
                        signature=payload.signature,
                        timestamp=payload.timestamp,
                    )
                    await pending.insert()
            except Exception as e:
                # Log but continue sending to other devices
                print(
                    f"Failed to send session key to device {key.device_id}: {e}")

        return BaseResponse(
            status_code=status.HTTP_200_OK,
            success=True,
            message=f"Session key sent to {sent_count} device(s)",
            data={
                "recipient_id": str(recipient_id),
                "devices_count": len(recipient_keys),
                "sent_count": sent_count,
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to exchange session key: {str(e)}",
        )


@router.get(
    "/pending-keys",
    response_model=BaseResponse[List[PendingKeyEnvelope]],
    status_code=status.HTTP_200_OK,
)
async def get_pending_keys(
    device_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
) -> BaseResponse[List[PendingKeyEnvelope]]:
    """
    Fetch pending (offline) session/group keys for current user.
    Optionally filter by device_id.

    Returns both:
    - Keys that haven't been delivered yet (delivered=False)
    - Keys that were delivered via WebSocket but not yet ACKed (delivered=True, not deleted)

    This allows frontend to retry processing keys that were received via WebSocket
    but couldn't be processed (e.g., E2EE not initialized yet).
    """
    query = {
        "recipient_user_id": current_user.id,
        "expires_at": {"$gt": datetime.utcnow()},
    }
    if device_id:
        query["recipient_device_id"] = device_id

    # Get all pending keys (both delivered and not delivered) that haven't expired
    # Frontend will ACK to delete them after successful processing
    pending = await PendingSessionKey.find(query).to_list()

    envelopes = [
        PendingKeyEnvelope(
            id=str(p.id),
            conversation_id=str(p.conversation_id)
            if p.conversation_id
            else None,
            recipient_user_id=str(p.recipient_user_id),
            recipient_device_id=p.recipient_device_id,
            key_version=p.key_version,
            encrypted_session_key=p.encrypted_session_key,
            sender_user_id=str(p.sender_user_id),
            signature=p.signature,
            timestamp=p.timestamp,
            created_at=p.created_at,
        )
        for p in pending
    ]

    return BaseResponse(
        status_code=status.HTTP_200_OK,
        success=True,
        message="Pending keys retrieved",
        data=envelopes,
    )


@router.post(
    "/pending-keys/ack",
    response_model=BaseResponse[dict],
    status_code=status.HTTP_200_OK,
)
async def ack_pending_keys(
    payload: PendingKeyAck,
    current_user: User = Depends(get_current_user),
) -> BaseResponse[dict]:
    """Mark pending keys as delivered (client has received/processed)."""
    try:
        logger.info(
            f"[E2EE] ACKing {len(payload.ids)} pending keys for user {current_user.id}")

        obj_ids = [ObjectId(pid) for pid in payload.ids]

        delete_result = await PendingSessionKey.find(
            {
                "_id": {"$in": obj_ids},
                "recipient_user_id": current_user.id,
            }
        ).delete()

        # Extract deleted count from DeleteResult (PyMongo DeleteResult uses 'n' attribute)
        deleted_count = getattr(delete_result, 'n', 0)

        logger.info(f"[E2EE] Deleted {deleted_count} pending keys")

        return BaseResponse(
            status_code=status.HTTP_200_OK,
            success=True,
            message="Pending keys acknowledged",
            data={"deleted": deleted_count},
        )
    except Exception as e:
        logger.error(f"[E2EE] Error in ack_pending_keys: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to acknowledge pending keys: {str(e)}",
        )
