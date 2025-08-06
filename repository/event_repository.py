from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
import uuid
from models import Event
from schema import EventCreateSchema, EventUpdateSchema
from datetime import datetime
#TODO FINISH ADDING GET_EVENT METHOD AND SERVICE LAYER METHODS
class EventRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_event(self, event: EventCreateSchema) -> Event:
        print(f"Creating new event: {event.name}")
        # Clean the datetime string and parse it
        #parsed_datetime = datetime.fromisoformat(event.datetime.replace('Z', '+00:00'))
        
        new_event = Event(
            id=uuid.uuid4(),
            name=event.name,
            description=event.description,
            date_time=datetime.fromisoformat(event.datetime),
            location=event.location,
            host_id=event.host_id
        )

        self.session.add(new_event)
        await self.session.commit()
        await self.session.refresh(new_event)
        print(f"Event created successfully with ID: {new_event.id}")
        return new_event

    async def get_all_events(self) -> list[Event]:
        print("Fetching all events from repository")
        result = await self.session.execute(select(Event))
        events = result.scalars().all()
        print(f"Found {len(events)} events in database")
        return events
    
    async def get_event_by_name(self, event_name: str):
        print(f"Fetching event with name: {event_name}")
        result = await self.session.execute(
            select(Event).where(Event.name == event_name)
        )
        event = result.scalar_one_or_none()
        if event:
            print(f"Event found: {event.name}")
        else:
            print("No event found with that name.")
        return event
    
    async def get_event_by_id(self, event_id: uuid.UUID):
        print(f"Fetching event with ID: {event_id}")
        result = await self.session.execute(
            select(Event).where(Event.id == event_id)
        )
        event = result.scalar_one_or_none()
        if event:
            print(f"Event found: {event.name}")
        else:
            print("No event found with that ID.")
        return event
    
    async def delete_event(self, event_id: str) -> bool:
        print(f"Attempting to delete event with ID: {event_id}")
        try:
            result = await self.session.execute(select(Event).where(Event.id == event_id))
            event = result.scalar_one()
            await self.session.delete(event)
            await self.session.commit()
            print(f"Event {event_id} deleted successfully")
            return True
        except NoResultFound:
            print(f"Event {event_id} not found for deletion")
            return False
        
    async def update_event(self, event_id: str, data: EventUpdateSchema) -> Event | None:
        print(f"Attempting to update event with ID: {event_id}")
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
            if data.host_id is not None:
                event.host_id = data.host_id

            await self.session.commit()
            await self.session.refresh(event)
            print(f"Event {event_id} updated successfully")
            return event
        except NoResultFound:
            print(f"Event {event_id} not found for update")
            return None