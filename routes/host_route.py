from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
import uuid
from handlers import create_host_handler, delete_host_handler, get_host_by_id_handler, get_host_by_email_handler
from database.session import get_async_session
from services import HostService
from models import Host
from schema import HostCreateSchema, HostReadSchema, HostUpdateSchema

router = APIRouter(prefix="/hosts", tags=["hosts"])
 
# Dependency to get HostService
async def get_user_service(session: AsyncSession = Depends(get_async_session))-> HostService:
    return HostService(session)
# POST 
@router.post("/", response_model=HostReadSchema, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_in: HostCreateSchema,   
    service: HostService = Depends(get_user_service),  # ✅ NO parentheses
):
    return await create_host_handler(user_in, service)

# DELETE
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: uuid.UUID,
    service: HostService = Depends(get_user_service),  # ✅ NO parentheses
):
    return await delete_host_handler(user_id, service)  

# GET 
@router.get("/by-id/{user_id}", response_model=HostReadSchema)
async def get_user(
    user_id: uuid.UUID,
    service: HostService = Depends(get_user_service),  # ✅ NO parentheses
):
    return await get_host_by_id_handler(user_id, service)
@router.get("/by-email/{email}", response_model=HostReadSchema)
async def get_user_by_email(
    email: EmailStr,
    service: HostService = Depends(get_user_service),  # ✅ NO parentheses
):
    return await get_host_by_email_handler(email, service)

# PATCH
@router.patch("/{user_id}", response_model=HostReadSchema)
async def update_user(
    user_id: uuid.UUID,
    user_in: HostUpdateSchema,
    service: HostService = Depends(get_user_service),  # ✅ NO parentheses
):
    return await service.update_host_service(user_id, user_in)

