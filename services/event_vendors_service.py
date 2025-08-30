import uuid
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException
from repository import EventVendorsRepository 
from models import EventVendor
from schema import EventVendorsCreateSchema, EventVendorsReadSchema, EventVendorsUpdateSchema, EventVendorSearchSchema
from config.logging_config import get_logger

logger = get_logger("service.event_vendors")

class EventVendorsService:
    def __init__(self, db: AsyncSession):
        self.event_vendors_repo = EventVendorsRepository(db)  

    async def create_event_vendor_service(self, data: EventVendorsCreateSchema) -> EventVendorsReadSchema:
        logger.info(f"Checking if event vendor record exists")
        existing = await self.event_vendors_repo.get_event_vendor(EventVendorSearchSchema(user_id=data.user_id, event_id=data.event_id))
        if existing:
            logger.warning(f"Event Vendor record creation filed: Vendor already assigned to event.")
            raise ValueError("Event Vendor record already exists.")
        
        new_event_vendor = await self.event_vendors_repo.create_event_vendor(data=data)
        logger.info(f"Event Vendor record created successfully")
        return new_event_vendor
    

    async def get_event_vendor_record_service(self, data: EventVendorSearchSchema) -> EventVendorsReadSchema:
        logger.info(f"Getting users with user ID and event ID: {data.user_id} and {data.event_id}")
        event_vendor = await self.event_vendors_repo.get_event_vendor(EventVendorSearchSchema(user_id=data.user_id, event_id=data.event_id))
        if not event_vendor:
            raise HTTPException(status_code=404, detail="Event Vendor not found")  
        return event_vendor
    
    async def get_vendors_for_event_service(self, data: EventVendorSearchSchema) -> List[EventVendorsReadSchema]:
        logger.info(f"Getting all vendors for event: {data.event_id}")
        event_vendors = await self.event_vendors_repo.get_vendors_by_event(EventVendorSearchSchema(event_id=data.event_id))
        
        if not event_vendors:
            raise HTTPException(status_code=404, detail="Event not found") 
         
        return_list = [self.event_vendors_repo.return_schema(event_vendor) for event_vendor in event_vendors]
        return return_list
    
    async def get_events_for_vendor_service(self, data: EventVendorSearchSchema) -> List[EventVendorsReadSchema]:
        logger.info(f"Getting all events for vendor: {data.user_id}")
        event_vendors = await self.event_vendors_repo.get_events_for_vendor(EventVendorSearchSchema(user_id=data.user_id))
        
        if not event_vendors:
            raise HTTPException(status_code=404, detail="Vendor has no events") 
        
        return_list = [self.event_vendors_repo.return_schema(event_vendor) for event_vendor in event_vendors]
        return return_list
    
    async def update_event_vendors_service(self, data: EventVendorsUpdateSchema) -> EventVendorsReadSchema: 
        logger.info(f"Updating information for vendor {data.user_id} for event {data.event_id}")
        updated_event_vendors = await self.event_vendors_repo.update_event_vendors(data=data)
        
        if not updated_event_vendors:
            raise HTTPException(status_code=404, detail="Vendor has no events or event not found") 
        
        return updated_event_vendors
    
    async def delete_event_vendor_service(self, data: EventVendorSearchSchema):
        logger.info(f"Deleting vendor {data.user_id} from event {data.event_id}")
        event_vendor_deleted = self.event_vendors_repo.delete_event_vendor(data=data)
        if event_vendor_deleted is False:
            raise HTTPException(status_code=404, detail="Unsuccessful deletion operation")


         

    