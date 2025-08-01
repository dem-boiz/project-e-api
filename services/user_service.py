import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from repository import UserRepository
from models import User
from schema import UserCreate


class UserService:
    def __init__(self, db: AsyncSession):
        self.repo = UserRepository(db)

    async def get_user_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        return await self.repo.get_user_by_id(user_id)

    async def get_user_by_email(self, email: str) -> Optional[User]:
        return await self.repo.get_user_by_email(email)

    async def create_user(self, user_data: UserCreate) -> User:
        # You might want to check if user already exists here:
        existing = await self.repo.get_user_by_email(user_data.email)
        if existing:
            raise ValueError("User already exists with this email.")

        return await self.repo.create_user(user_data)

    async def soft_delete_user(self, user_id: uuid.UUID) -> bool:
        user = await self.repo.get_user_by_id(user_id)
        if not user:
            return False
        user.is_deleted = True
        await self.repo.session.commit()
        return True

    async def list_users(self) -> list[User]:
        return await self.repo.list_users()
