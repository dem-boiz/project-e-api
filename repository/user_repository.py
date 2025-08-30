from typing import Optional, Sequence
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from models.user import User 
from schema import UserCreateSchema, UserReadSchema, UserUpdateSchema
import uuid
from passlib.context import CryptContext
# Password hashing context - suppress bcrypt version warnings
pwd_context = CryptContext(
    schemes=["bcrypt"], 
    deprecated="auto",
    bcrypt__rounds=10  # The number of hashing rounds. Higher = more secure but slower
) 

class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session 

    def return_schema(self, user: User): 
        return UserReadSchema(id=user.id, email=user.email, name=user.name, user_number=user.user_number,  created_at=user.created_at, 
                                  updated_at=user.updated_at, is_deleted=user.is_deleted, is_active=user.is_active)
 
    async def create_user(self, data: UserCreateSchema) -> UserReadSchema:
        """Create a new user with unique UUID and additional information"""
        password_hash = pwd_context.hash(data.password)
        new_user = User(email=data.email, password_hash=password_hash, name=data.name)
        self.session.add(new_user)
        await self.session.commit()
        await self.session.refresh(new_user) 
        return self.return_schema(new_user)

    async def get_user_by_id(self, user_id: uuid.UUID) -> UserReadSchema | None:
        """Fetch user by UUID. Returns None if not found."""
        try:
            result = await self.session.execute(
                select(User).where(User.id == user_id)
            )
            user = result.scalar_one() 
            return self.return_schema(user)
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
    
    async def update_user(self, user_id: uuid.UUID, data: UserUpdateSchema) -> Optional[User]:
        try:
            result = await self.session.execute(select(User).where(User.id == user_id))
            user = result.scalar_one()
            # Update only fields provided (not None)
            if data.email is not None:
                user.email = data.email
            if data.company_name is not None:
                user.company_name = data.company_name
            if data.password is not None: 
                user.password_hash = pwd_context.hash(data.password)

            await self.session.commit()
            await self.session.refresh(user)
            return user

        except NoResultFound:
            return None