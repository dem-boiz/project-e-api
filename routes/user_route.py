from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
import uuid

from database.session import get_async_session
from repository import UserRepository
from models.user import User
from schema import UserCreate, UserRead

router = APIRouter(prefix="/users", tags=["users"])
 
# Dependency to get UserRepository
async def get_user_repo(session: AsyncSession = Depends(get_async_session)):
    return UserRepository(session)


@router.post("/", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(user_in: UserCreate, repo: UserRepository = Depends(get_user_repo)):
    # Check if email exists
    existing = await repo.get_user_by_email(user_in.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = await repo.create_user(email=user_in.email)
    return user


@router.get("/{user_id}", response_model=UserRead)
async def get_user(user_id: uuid.UUID, repo: UserRepository = Depends(get_user_repo)):
    user = await repo.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("/by-email/{email}", response_model=UserRead)
async def get_user_by_email(email: EmailStr, repo: UserRepository = Depends(get_user_repo)):
    user = await repo.get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
