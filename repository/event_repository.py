from typing import Sequence
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
import uuid
from models import Event
from schema import EventCreateSchema, EventUpdateSchema
from datetime import datetime

from schema.event_schemas import EventReadSchema
class EventRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_event(self, event: EventCreateSchema, host_id: uuid.UUID) -> EventReadSchema:
        # Clean the datetime string and parse it
        #parsed_datetime = datetime.fromisoformat(event.datetime.replace('Z', '+00:00'))
        
        new_event = Event(
            id=uuid.uuid4(),
            name=event.name,
            description=event.description,
            date_time=datetime.fromisoformat(event.datetime),
            location=event.location,
            host_id=host_id,
            event_images=[]
        )

        self.session.add(new_event)
        await self.session.commit()
        await self.session.refresh(new_event)
        return EventReadSchema.model_validate(new_event)

    async def get_all_events(self) -> Sequence[EventReadSchema]:
        result = await self.session.execute(select(Event))
        events = result.scalars().all()
        return [EventReadSchema.model_validate(event) for event in events]

    async def get_event_by_name(self, event_name: str) -> EventReadSchema | None:
        result = await self.session.execute(
            select(Event).where(Event.name == event_name)
        )
        event = result.scalar_one_or_none()

        return EventReadSchema.model_validate(event) if event else None
    

    async def get_events_hosted_by_user(self, user_id: uuid.UUID) -> Sequence[EventReadSchema]:
        result = await self.session.execute(
            select(Event).where(Event.host_id == user_id)
        )
        events = result.scalars().all()
        return [EventReadSchema.model_validate(event) for event in events]

    async def get_event_by_id(self, event_id: uuid.UUID) -> EventReadSchema | None:
        result = await self.session.execute(
            select(Event).where(Event.id == event_id)
        )
        event = result.scalar_one_or_none()
        if event:
            return EventReadSchema.model_validate(event)
        return None

    async def get_events_by_ids(self, event_ids: list[uuid.UUID]) -> Sequence[EventReadSchema]:
        result = await self.session.execute(
            select(Event).where(Event.id.in_(event_ids))
        )
        events = result.scalars().all()
        event_schemas = [EventReadSchema.model_validate(event) for event in events]
        return event_schemas

    async def delete_event(self, event_id: uuid.UUID) -> bool:
        try:
            result = await self.session.execute(select(Event).where(Event.id == event_id))
            event = result.scalar_one()
            await self.session.delete(event)
            await self.session.commit()
            return True
        except NoResultFound:
            return False
        
    async def update_event(self, event_id: uuid.UUID, data: EventUpdateSchema) -> EventReadSchema | None:
        try:
            result = await self.session.execute(select(Event).where(Event.id == event_id))
            event = result.scalar_one()
            
            # Only update fields that are provided (not None)
            if data.name is not None:
                event.name = data.name
            if data.description is not None:
                event.description = data.description
            if data.location is not None:
                event.location = data.location
            if data.datetime is not None:
                event.date_time = datetime.fromisoformat(data.datetime)

            await self.session.commit()
            await self.session.refresh(event)
            return EventReadSchema.model_validate(event)
        except NoResultFound:
            return None