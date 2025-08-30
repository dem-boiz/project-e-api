from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from models import EventVendor
from schema import EventVendorsReadSchema, EventVendorsCreateSchema, EventVendorsUpdateSchema
import uuid
from datetime import datetime


class EventVendorsRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    def return_schema(self, data: EventVendor):
        return EventVendorsReadSchema(event_id=data.event_id, user_id=data.user_id, event_date=data.event_date, added_at=datetime.now())

    async def create_event_vendor(self, data: EventVendorsCreateSchema) -> EventVendorsReadSchema:
        new_event_vendor = EventVendor(event_id=data.event_id, user_id=data.user_id, event_date=data.event_date)
        self.session.add(new_event_vendor)
        await self.session.commit()
        await self.session.refresh(new_event_vendor)
        return EventVendorsReadSchema(event_id=data.event_id, user_id=data.user_id, event_date=data.event_date, added_at=datetime.now())
    
    async def get_event_vendor(self, user_id: uuid.UUID, event_id: uuid.UUID) -> EventVendorsReadSchema | None:
        try:
            result = await self.session.execute(
                select(EventVendor).where(EventVendor.user_id == user_id and EventVendor.event_id == event_id)
            )
            event_vendor = result.scalar_one()
            return self.return_schema(event_vendor)
        except NoResultFound:
            return None
        

    async def get_vendors_by_event(self, event_id: uuid.UUID) -> List[EventVendor] | None:
        try:
            result = await self.session.execute(
                select(EventVendor).where(EventVendor.event_id == event_id)
            ) 
            return list(result.scalars().all())
        except NoResultFound:
            return None
        
    async def get_events_for_vendor(self, user_id: uuid.UUID) -> List[EventVendor] | None:
        try:
            result = await self.session.execute(
                select(EventVendor).where(EventVendor.user_id == user_id)
            ) 
            return list(result.scalars().all())
        except NoResultFound:
            return None
        
    async def update_user(self, data: EventVendorsUpdateSchema) -> EventVendorsReadSchema | None:
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


