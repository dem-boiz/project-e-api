from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
import uuid
from handlers import create_user_handler, get_user_by_id_handler, hard_delete_user_handler, get_user_by_email_handler
from database.session import get_async_session
from services import UserService
from models.user import User
from schema import UserCreateSchema, UserReadSchema

router = APIRouter(prefix="/users", tags=["users"])
 
# Dependency to get UserService
async def get_user_service(session: AsyncSession = Depends(get_async_session))-> UserService:
    return UserService(session)


@router.post("/", response_model=UserReadSchema, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_in: UserCreateSchema,   
    service: UserService = Depends(get_user_service),  # ✅ NO parentheses
):
    return await create_user_handler(user_in, service)
 

@router.get("/get/by-id/{user_id}", response_model=UserReadSchema)
async def get_user(user_id: uuid.UUID, service: UserService = Depends(get_user_service)):
    return await get_user_by_id_handler(user_id, service)


@router.get("/get/by-email/{email}", response_model=UserReadSchema)
async def get_user_by_email(email: EmailStr, service: UserService = Depends(get_user_service)):
    return await get_user_by_email_handler(email, service)
 
@router.delete("/delete/by-id", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: uuid.UUID, service: UserService = Depends(get_user_service)):
    return await hard_delete_user_handler(user_id, service)