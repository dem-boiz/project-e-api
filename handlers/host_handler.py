from fastapi import Depends, status, HTTPException
from services import HostService
from schema import HostCreateSchema, HostUpdateSchema
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
from models import Host
from database.session import get_async_session
import uuid

async def create_host_handler(user_in: HostCreateSchema, service: HostService) -> Host:
    return await service.create_host(user_in)

async def delete_host_handler(user_id: uuid.UUID, service: HostService):
    return await service.delete_host_by_id(user_id)

async def get_host_by_id_handler(user_id: uuid.UUID, service: HostService):
    return await service.get_host_by_id(user_id)

async def get_host_by_email_handler(email: EmailStr, service: HostService):
    return await service.get_host_by_email(email)