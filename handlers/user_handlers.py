from fastapi import Depends, status, HTTPException
from services import UserService
from schema import UserCreateSchema, UserReadSchema
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
from database.session import get_async_session
import uuid

async def create_user_handler(user_in: UserCreateSchema, service: UserService):
    return await service.create_user_service(user_in) 

async def get_user_by_id_handler(user_id: uuid.UUID, service: UserService):
    return await service.get_user_by_id(user_id)

async def hard_delete_user_handler(user_id: uuid.UUID, service: UserService):
    return await service.hard_delete_user(user_id)
 
async def get_user_by_email_handler(email: EmailStr, service: UserService):
    return await service.get_user_by_email(email)