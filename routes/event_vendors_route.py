from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
import uuid
from handlers import create_event_vendor_handler, update_event_vendors_handler, delete_event_vendors_handler, get_vendors_for_event_handler, get_event_vendor_record_handler, get_events_for_vendor_handler
from database.session import get_async_session
from services import EventVendorsService
from models.user import User
from schema import EventVendorsReadSchema, EventVendorSearchSchema, EventVendorsCreateSchema, EventVendorsUpdateSchema

router = APIRouter(prefix="/event-vendors", tags=["event-vendors"])
 
# Dependency to get EventVendor
async def get_event_vendor_service(session: AsyncSession = Depends(get_async_session))-> EventVendorsService:
    return EventVendorsService(session)


@router.post("/", response_model=EventVendorsReadSchema, status_code=status.HTTP_201_CREATED)
async def create_event_vendor(
    data: EventVendorsCreateSchema,
    service: EventVendorsService = Depends(get_event_vendor_service)
):
    return await create_event_vendor_handler(data=data, service=service)
    
@router.get("/", response_model=EventVendorsReadSchema, status_code=status.HTTP_302_FOUND)
async def get_event_vendor(
    data: EventVendorSearchSchema = Depends(),
    service: EventVendorsService = Depends(get_event_vendor_service)
):
    return await get_event_vendor_record_handler(data=data, service=service)

@router.get("/user-id", response_model=List[EventVendorsReadSchema], status_code=status.HTTP_302_FOUND)
async def get_events_for_vendor(
    data: EventVendorSearchSchema = Depends(),
    service: EventVendorsService = Depends(get_event_vendor_service)
):
    return await get_events_for_vendor_handler(data=data, service=service)

@router.get("/event-id", response_model=List[EventVendorsReadSchema], status_code=status.HTTP_302_FOUND)
async def get_vendors_for_event(
    data: EventVendorSearchSchema = Depends(),
    service: EventVendorsService = Depends(get_event_vendor_service)
):
    return await get_vendors_for_event_handler(data=data, service=service)


@router.patch("/", response_model=EventVendorsReadSchema, status_code=status.HTTP_202_ACCEPTED)
async def update_user(
    data: EventVendorsUpdateSchema = Depends(), 
    service: EventVendorsService = Depends(get_event_vendor_service)
):
    return await update_event_vendors_handler(data=data, service=service)


@router.delete("/", status_code=status.HTTP_204_NO_CONTENT)
async def delete_event_vendor(
    data: EventVendorSearchSchema = Depends(),
    service: EventVendorsService = Depends(get_event_vendor_service)
):
    return await delete_event_vendors_handler(data=data, service=service)