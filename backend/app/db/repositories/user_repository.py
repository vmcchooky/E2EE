from app.db.models import User


class UserRepository:
    """Encapsulates CRUD operations for users using Beanie."""

    async def get_by_email(self, email: str) -> User | None:
        return await User.find_one(User.email == email)

    async def get_by_username(self, username: str) -> User | None:
        return await User.find_one(User.username == username)

    async def get_by_id(self, user_id: str) -> User | None:
        return await User.get(user_id)

    async def save(self, user: User) -> User:
        return await user.insert()


