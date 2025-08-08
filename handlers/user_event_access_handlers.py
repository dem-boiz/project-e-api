from fastapi import Depends, status, HTTPException
from services import UserEventAccessService
from schema import UserEventAccessReadSchema, UserEventAccessCreateSchema
from sqlalchemy.ext.asyncio import AsyncSession
from database.session import get_async_session

async def create_user_access_event_handler(user_event_access_in: UserEventAccessCreateSchema, service: UserEventAccessService) -> UserEventAccessReadSchema:
    return await service.create_user_event_access(user_event_access_in)