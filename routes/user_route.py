from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
import uuid

from database.session import get_async_session
from services import UserService
from models.user import User
from schema import UserCreate, UserRead

router = APIRouter(prefix="/users", tags=["users"])
 
# Dependency to get UserService
async def get_user_service(session: AsyncSession = Depends(get_async_session)):
    return UserService(session)


@router.post("/create", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(user_in: UserCreate, 
                      service: UserService = Depends(get_user_service)):
    # Check if email exists
    existing = await service.get_user_by_email(user_in.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = await service.create_user(user_in)
    return user


@router.get("/get/by-id/{user_id}", response_model=UserRead)
async def get_user(user_id: uuid.UUID, service: UserService = Depends(get_user_service)):
    user = await service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("/get/by-email/{email}", response_model=UserRead)
async def get_user_by_email(email: EmailStr, service: UserService = Depends(get_user_service)):
    user = await service.get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user  
 
@router.delete("/delete/by-id", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: uuid.UUID, service: UserService = Depends(get_user_service)):
    # Check if the user exists
    existing = await service.get_user_by_id(user_id)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Delete the user
    await service.hard_delete_user(user_id)
    return None  # No content to return
 