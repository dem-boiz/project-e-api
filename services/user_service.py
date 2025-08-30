import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException
from repository import UserRepository 
from models import User
from schema import UserCreateSchema, UserReadSchema, UserUpdateSchema 
from config.logging_config import get_logger

logger = get_logger("service.user")

class UserService:
    def __init__(self, db: AsyncSession):
        self.user_repo = UserRepository(db)  

    async def get_user_by_id(self, user_id: uuid.UUID) -> Optional[UserReadSchema]:
        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user 
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        user = await self.user_repo.get_user_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")   
        return user

    async def create_user_service(self, data: UserCreateSchema) -> UserReadSchema:
        logger.info(f"Checking if user exists with email '{data.email}'")
        existing = await self.user_repo.get_user_by_email(email=data.email)
        if existing:
            logger.warning(f"User creation failed: User already exists with email '{data.email}'")
            raise ValueError("User already exists with this email.")   
        new_user = await self.user_repo.create_user(data) 
        logger.info(f"User created successfully: {data.name}")
        return new_user

    async def soft_delete_user(self, user_id: uuid.UUID) -> bool:
        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            return False
        user.is_deleted = True
        await self.user_repo.session.commit()
        return True

    async def hard_delete_user(self, user_id: uuid.UUID) -> bool:
        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return await self.user_repo.delete_user_by_id(user_id)
            

    async def list_users(self) -> list[User]:
        try: 
            users = await self.user_repo.list_users()
            return list(users)
        except:
            raise HTTPException(status_code=404, detail="Users not found")
