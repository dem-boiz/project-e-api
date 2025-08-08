from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
import uuid
from handlers import create_user_handler, get_user_by_id_handler, hard_delete_user_handler, get_user_by_email_handler
from database.session import get_async_session
from services import UserEventAccessService
from models import UserEventAccess
from schema import UserEventAccessCreateSchema, UserEventAccessReadSchema

router = APIRouter(prefix="/user-event-access", tags=["user-event-access"])
 
# Dependency to get UserEventAccessService
async def get_user_event_access_service(session: AsyncSession = Depends(get_async_session))-> UserEventAccessService:
    return UserEventAccessService(session)

@router.post("/", response_model=UserEventAccessReadSchema, status_code=status.HTTP_201_CREATED)
async def create_user_event_access(
    user_event_access_in: UserEventAccessCreateSchema,   
    service: UserEventAccessService = Depends(get_user_event_access_service),  # ✅ NO parentheses
):
    return await service.create_user_event_access(user_event_access_in)