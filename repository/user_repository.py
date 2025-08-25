from typing import Sequence
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from models.user import User
import uuid


class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_user(self, email: str) -> User:
        """Create a new user with a unique UUID and email."""
        new_user = User(email=email)
        self.session.add(new_user)
        await self.session.commit()
        await self.session.refresh(new_user)
        return new_user

    async def get_user_by_id(self, user_id: uuid.UUID) -> User | None:
        """Fetch user by UUID. Returns None if not found."""
        try:
            result = await self.session.execute(
                select(User).where(User.id == user_id)
            )
            user = result.scalar_one()
            return user
        except NoResultFound:
            return None

    async def get_user_by_email(self, email: str) -> User | None:
        """Fetch user by email. Returns None if not found."""
        try:
            result = await self.session.execute(
                select(User).where(User.email == email)
            )
            user = result.scalar_one()
            return user
        except NoResultFound:
            return None

    async def delete_user_by_id(self, user_id: uuid.UUID) -> bool:
        """Delete user by id. Returns True if deleted, False if not found."""
        user = await self.get_user_by_id(user_id)
        if user is None:
            return False
        await self.session.delete(user)
        await self.session.commit()
        return True
    
    async def delete_user_by_email(self, email: str) -> bool:
        """Delete user by id. Returns True if deleted, False if not found."""
        user = await self.get_user_by_email(email)
        if user is None:
            return False
        await self.session.delete(user)
        await self.session.commit()
        return True
    
    async def list_users(self) -> Sequence[User]:
            result = await self.session.execute(select(User))
            return result.scalars().all()