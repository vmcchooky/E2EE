from fastapi import Depends, HTTPException, status
from bson import ObjectId

from app.db.models.friend import Friend
from app.db.models import User
from app.db.models.conversation import Conversation
from app.dependencies.auth import get_current_user
from app.schemas.chats import DirectMessagePayload, GroupMessagePayload


def normalize_pair(user_a: ObjectId, user_b: ObjectId) -> tuple[ObjectId, ObjectId]:
    """
    Chuẩn hóa thứ tự 2 user: userA luôn < userB.
    """
    return (user_a, user_b) if user_a < user_b else (user_b, user_a)


async def check_friendship(
    payload: DirectMessagePayload,
    current_user: User = Depends(get_current_user),
) -> None:
    """
    Kiểm tra xem current_user và recipient có phải là bạn bè không.

    Args:
        current_user_id: ObjectId của user hiện tại
        recipient_id: ID của người nhận (có thể là string hoặc ObjectId)

    Returns:
        True nếu là bạn bè, False nếu không có recipient_id

    Raises:
        HTTPException: Nếu recipient_id được cung cấp nhưng không phải bạn bè
    """
    try:
        # Lấy recipient_id từ payload
        recipient_id = payload.recipient_id

        # Nếu không có recipient_id thì không cần check
        if not recipient_id:
            return False

        # Convert recipient_id sang ObjectId nếu là string
        if isinstance(recipient_id, str):
            if not ObjectId.is_valid(recipient_id):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="recipient_id không hợp lệ",
                )
            recipient_id = ObjectId(recipient_id)

        # Kiểm tra không thể gửi cho chính mình
        if current_user.id == recipient_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Không thể gửi tin nhắn cho chính mình",
            )

        # Normalize thứ tự userA và userB
        user_a, user_b = normalize_pair(current_user.id, recipient_id)

        # Kiểm tra friendship
        is_friend = await Friend.find_one(
            Friend.userA == user_a, Friend.userB == user_b
        )

        if not is_friend:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Không thể gửi tin nhắn cho người không phải bạn bè",
            )

        return True
    except HTTPException:
        # Re-raise HTTPException as is (don't convert to 500)
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Lỗi khi kiểm tra bạn bè: {str(e)}",
        )


async def check_group_membership(
    payload: GroupMessagePayload,
    current_user: User = Depends(get_current_user),
) -> None:
    try:
        conversation_id = payload.conversation_id
        
        if not ObjectId.is_valid(conversation_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="conversation_id không hợp lệ",
            )
        conv_id = ObjectId(conversation_id)

        # Kiểm tra thành viên nhóm
        conversation = await Conversation.get(conv_id)
        if not conversation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cuộc trò chuyện không tồn tại",
            )

        is_member = any(
            participant.user_id == current_user.id
            for participant in conversation.participants
        )

        if not is_member:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Bạn không phải thành viên của cuộc trò chuyện này",
            )

        return True
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Lỗi khi kiểm tra thành viên nhóm: {str(e)}",
        )
