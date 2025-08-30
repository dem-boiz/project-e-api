from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from models import EventVendor
from schema import EventVendorsReadSchema, EventVendorsCreateSchema
import uuid
from datetime import datetime


class EventVendorsRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_event_vendor(self, data: EventVendorsCreateSchema) -> EventVendorsReadSchema:
        new_event_vendor = EventVendor(event_id=data.event_id, user_id=data.user_id, event_date=data.event_date)
        self.session.add(new_event_vendor)
        await self.session.commit()
        await self.session.refresh(new_event_vendor)
        return EventVendorsReadSchema(event_id=data.event_id, user_id=data.user_id, event_date=data.event_date, added_at=datetime.now())

