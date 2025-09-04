from typing import List
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from models import EventVendor
from schema import EventVendorsReadSchema, EventVendorsCreateSchema, EventVendorsUpdateSchema, EventVendorSearchSchema
import uuid
from datetime import datetime


class EventVendorsRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    def return_schema(self, data: EventVendor):
        return EventVendorsReadSchema(event_id=data.event_id, user_id=data.user_id, added_at=datetime.now())

    async def create_event_vendor(self, data: EventVendorsCreateSchema) -> EventVendorsReadSchema:
        new_event_vendor = EventVendor(event_id=data.event_id, user_id=data.user_id)
        self.session.add(new_event_vendor)
        await self.session.commit()
        await self.session.refresh(new_event_vendor)
        return EventVendorsReadSchema(event_id=data.event_id, user_id=data.user_id, added_at=datetime.now())
    
    async def get_event_vendor(self, data: EventVendorSearchSchema) -> EventVendorsReadSchema | None:
        try:
            result = await self.session.execute(
                select(EventVendor).where(EventVendor.user_id == data.user_id and EventVendor.event_id == data.event_id)
            )
            event_vendor = result.scalar_one()
            return self.return_schema(event_vendor)
        except NoResultFound:
            return None
        

    async def get_vendors_by_event(self, data: EventVendorSearchSchema) -> List[EventVendor] | None:
        try:
            result = await self.session.execute(
                select(EventVendor).where(EventVendor.event_id == data.event_id)
            )
             
            return list(result.scalars().all())
        except NoResultFound:
            return None
        
    async def get_events_for_vendor(self, data: EventVendorSearchSchema) -> List[EventVendor] | None:
        try:
            result = await self.session.execute(
                select(EventVendor).where(EventVendor.user_id == data.user_id)
            ) 
            return list(result.scalars().all())
        except NoResultFound:
            return None

    async def delete_event_vendor(self, data: EventVendorSearchSchema) -> bool:
        event_vendor = await self.get_event_vendor(data=data)

        if event_vendor is None:
            return False
        
        await self.session.delete(event_vendor)
        await self.session.commit()
        return True
    
    async def delete_vendors_for_event(self, data: EventVendorSearchSchema) -> int:
        result = await self.session.execute(
            delete(EventVendor).where(EventVendor.event_id == data.event_id)
        )

        if result is None:
            return 0
    
        await self.session.commit()
        return result.rowcount
    
    async def delete_vendor_from_events(self, data: EventVendorSearchSchema) -> int:
        result = await self.session.execute(
            delete(EventVendor).where(EventVendor.user_id == data.user_id)
        )

        if result is None:
            return 0
    
        await self.session.commit()
        return result.rowcount
        
    async def update_event_vendors(self, data: EventVendorsUpdateSchema) -> EventVendorsReadSchema | None:
        try:
            # Check if updating a specific vendor in an event 
            if data.event_id is not None:
                result = await self.session.execute(
                    select(EventVendor)
                    .where(EventVendor.user_id == data.user_id 
                           and EventVendor.event_id == data.event_id
                           )
                    )
                
                event_vendor = result.scalar_one()
                if data.vendor_description is not None:
                    event_vendor.vendor_description = data.vendor_description
                
                if data.vendor_images is not None:
                    event_vendor.vendor_images = data.vendor_images
                await self.session.commit()
                await self.session.refresh(event_vendor)
                return self.return_schema(event_vendor)
            # Or if updating this vendor for all events
            else:
                # Get all matching Event Vendor records with user_id
                result = await self.session.execute(
                    select(EventVendor)
                    .where(EventVendor.user_id == data.user_id)
                )
                event_vendors = result.scalars().all()

                # Check if description and/or images being updated and update
                for event_vendor in event_vendors:
                    if data.vendor_description is not None:
                        event_vendor.vendor_description = data.vendor_description
                
                    if data.vendor_images is not None:
                        event_vendor.vendor_images = data.vendor_images

                    await self.session.commit()
                    await self.session.refresh(event_vendor)

                return self.return_schema(event_vendors[0])

                
        except NoResultFound:
            return None


