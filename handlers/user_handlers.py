from fastapi import Depends, status, HTTPException
from services import UserService
from schema import UserCreate, UserRead
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
from database.session import get_async_session
import uuid

async def create_user_handler(user_in: UserCreate, service: UserService):
    # Check if email exists
    existing = await service.get_user_by_email(user_in.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = await service.create_user(user_in)
    return user

async def get_user_by_id_handler(user_id: uuid.UUID, service: UserService):
    user = await service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

async def delete_user_handler(user_id: uuid.UUID, service: UserService):
    # Check if the user exists
    existing = await service.get_user_by_id(user_id)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Delete the user
    await service.hard_delete_user(user_id)
    return None  # No content to return
 
async def get_user_by_email(email: EmailStr, service: UserService):
    user = await service.get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user  