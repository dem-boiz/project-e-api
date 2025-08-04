from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
import uuid
from models.event import Event
from schema.event_schemas import EventCreateSchema

class EventRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_event(self, event: EventCreateSchema) -> Event:
        new_event = Event(
            id=uuid.uuid4(),
            name=event.name,
            description=event.description,
            date=event.date_time,
            location=event.location

        )

        self.session.add(new_event)
        await self.session.commit()
        await self.session.refresh(new_event)
        return new_event

    async def get_all_events(self) -> list[Event]:
        print("Fetching all events from repository")
        result = await self.session.execute(select(Event))
        return result.scalars().all()
    
    async def delete_event(self, event_id: str) -> bool:
        try:
            result = await self.session.execute(select(Event).where(Event.id == event_id))
            event = result.scalar_one()
            await self.session.delete(event)
            await self.session.commit()
            return True
        except NoResultFound:
            return False
        
    async def update_event(self, event_id: str, data: EventCreateSchema) -> Event | None:
        try:
            result = await self.session.execute(select(Event).where(Event.id == event_id))
            event = result.scalar_one()
            event.event_name = data.name
            event.description = data.description
            event.event_datetime = data.datetime
            event.location = data.location

            await self.session.commit()
            await self.session.refresh(event)
            return event
        except NoResultFound:
            return None