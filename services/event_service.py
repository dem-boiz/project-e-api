import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

from repository import EventRepository
from models import Event 
from schema import EventCreateSchema, EventUpdateSchema

class EventService:
    def __init__(self, db: AsyncSession):
        self.repo = EventRepository(db)

    async def create_event_service(self, event_data: EventCreateSchema) -> Event:
        # Check if an event with the same name already exists here:
        existing = await self.repo.get_event_by_name(event_data.name)   
        if existing:
            # TODO: When this is raised, the client gets a 500 response. refactor to be a 422 or 409
            raise ValueError("Event already exists with this name.")
        
        ''' # TODO: Implement the functions in repository to check these conditions
        # Check if the host exists
        host = await self.repo.get_user_by_id(event_data.host_id)
        if not host:
            raise ValueError("Host does not exist.")
        
        # Check if the host is hosting too many events
        if await self.repo.count_hosted_events(event_data.host_id) >= 5:
            raise ValueError("Host is already hosting too many events.")    
        
        # Check if the host is hosting an event at the same time
        overlapping_event = await self.repo.get_event_at_same_time(event_data.host_id, event_data.datetime)
        if overlapping_event:   
            raise ValueError("Host is already hosting an event at this time.")  
            
        # Check if the event start time is before the end time
        if event_data.start_time >= event_data.end_time:    
            raise ValueError("Event start time must be before the end time.") 
        '''
        
        # Check if the event date is in the past
        event_datetime = datetime.fromisoformat(event_data.datetime)
        now = datetime.now(event_datetime.tzinfo) if event_datetime.tzinfo else datetime.now()
        if event_datetime < now:
            raise ValueError("Event date cannot be in the past.")   
        
        # Check if the event location name is valid
        if not event_data.location or len(event_data.location) < 5:
            raise ValueError("Event location must be at least 5 characters long.")  
        
        # Check if the event description is valid
        if not event_data.description or len(event_data.description) < 10:
            raise ValueError("Event description must be at least 10 characters long.")
        
        
        # Check if the event name is valid
        if not event_data.name or len(event_data.name) < 3: 
            raise ValueError("Event name must be at least 3 characters long.")
        
        

        # If all checks pass, create the event
        return await self.repo.create_event(event_data)
    
    async def get_event_by_id_service(self, event_id: uuid.UUID) -> Event:
        # Check if the event exists
        event = await self.repo.get_event_by_id(event_id)
        if not event:
            raise ValueError("Event with the specified ID does not exist.")
        
        return event
    
    async def get_event_by_name_service(self, name: str) -> Event:
        # Check if the event exists
        event = await self.repo.get_event_by_name(name)
        if not event:
            raise ValueError("Event with the specified name does not exist.")
        
        return event
    
    async def get_all_events_service(self) -> list[Event]:
        return await self.repo.get_all_events()
    
    async def update_event_service(self, event_id: uuid.UUID, data: EventUpdateSchema) -> Event:
        # Check if the event exists
        event = await self.repo.get_event_by_id(event_id)
        if not event:
            raise ValueError("Event with the specified ID does not exist.")
        
        # Update the event details
        for key, value in data.dict(exclude_unset=True).items():
            setattr(event, key, value)
        
        return await self.repo.update_event(event_id, data)
    
    async def delete_event_service(self, event_id: uuid.UUID) -> bool:
        # Check if the event exists
        event = await self.repo.get_event_by_id(event_id)
        if not event:
            raise ValueError("Event with the specified ID does not exist.")
        
        return await self.repo.delete_event(event_id)
    
    