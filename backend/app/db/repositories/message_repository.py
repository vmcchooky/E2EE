from sqlalchemy.orm import Session

from app.db.models import Message


class MessageRepository:
    """CRUD helpers for encrypted messages."""

    def __init__(self, db: Session):
        self.db = db

    async def save(self, message: Message) -> Message:
        self.db.add(message)
        self.db.commit()
        self.db.refresh(message)
        return message


