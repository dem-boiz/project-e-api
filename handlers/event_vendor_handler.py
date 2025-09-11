from typing import List
from fastapi import Depends, status, HTTPException
from services import EventVendorsService, VendorImagesService
from schema import VendorImagesCreateSchema, VendorImagesReadSchema, EventVendorSearchSchema, EventVendorsCreateSchema, EventVendorsReadSchema, EventVendorsUpdateSchema, EventVendorClientSchema
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
from database.session import get_async_session
import uuid

async def create_event_vendor_handler(data: EventVendorsCreateSchema, service: EventVendorsService):
    return await service.create_event_vendor_service(data=data)

async def get_event_vendor_record_handler(data: EventVendorSearchSchema, service: EventVendorsService) -> EventVendorsReadSchema:
    return await service.get_event_vendor_record_service(data=data) 

async def get_events_for_vendor_handler(data: EventVendorSearchSchema, service: EventVendorsService) -> List[EventVendorsReadSchema]:
    return await service.get_events_for_vendor_service(data=data) 

async def get_vendors_for_event_handler(data: EventVendorSearchSchema, service: EventVendorsService) -> List[EventVendorClientSchema]:
    return await service.get_vendors_for_event_service(data=data)

async def update_event_vendors_handler(data: EventVendorsUpdateSchema, service: EventVendorsService) -> EventVendorsReadSchema:
    return await service.update_event_vendors_service(data=data)

async def delete_event_vendors_handler(data: EventVendorSearchSchema, service: EventVendorsService):
    return await service.delete_event_vendor_service(data=data)

async def delete_vendors_for_event_handler(data: EventVendorSearchSchema, service: EventVendorsService) -> int:
    return await service.delete_vendors_for_event_service(data=data)

async def delete_vendor_from_events_handler(data: EventVendorSearchSchema, service: EventVendorsService):
    return await service.delete_vendor_from_events_service(data=data)

async def add_vendor_image_handler(data: VendorImagesCreateSchema, service: VendorImagesService) -> VendorImagesReadSchema:
    return await service.add_vendor_image_service(data=data)

async def get_vendor_image_handler(event_vendor_id: uuid.UUID, service: VendorImagesService) -> List[VendorImagesReadSchema]:
    return await service.get_vendor_images_for_event_vendor_service(event_vendor_id=event_vendor_id)