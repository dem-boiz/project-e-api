# Dependency to get EventService
from services.auth_service import AuthService
from services.event_service import EventService
from services.invite_service import InviteService
from sqlalchemy.ext.asyncio import AsyncSession
from database.session import get_async_session
from fastapi import Depends

async def get_event_service(session: AsyncSession = Depends(get_async_session))-> EventService:
    return EventService(session)

# Dependency to get AuthService for authentication
async def get_auth_service(session: AsyncSession = Depends(get_async_session)) -> AuthService:
    return AuthService(session)

async def get_invite_service(session: AsyncSession = Depends(get_async_session)) -> InviteService:
    return InviteService(session)
