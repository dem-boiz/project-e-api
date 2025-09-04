import uuid
from typing import Sequence
from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

from config.logging_config import get_logger
from database.session import get_async_session
from models.device_grant import DeviceGrant
from models.user_grant import UserGrant
from repository import EventRepository
from models import Event 
from repository.user_repository import UserRepository
from schema import EventCreateSchema, EventUpdateSchema
from schema.user_grant_schemas import UserGrantCreateSchema
from services.device_grant_service import DeviceGrantService
from services.invite_service import InviteService
from services.user_grant_service import UserGrantService


#TODO: add logging


logger = get_logger("api.events")
class EventService:
    def __init__(self, db: AsyncSession):
        self.repo = EventRepository(db)
        self.user_repo = UserRepository(db)
    async def create_event(self, event_data: EventCreateSchema, user_id: uuid.UUID) -> Event:

        ''' # TODO: Implement the functions in repository to check these conditions
    
        # Check if the host is hosting too many events
        if await self.repo.count_hosted_events(event_data.host_id) >= 5:
            raise ValueError(" is already hosting too many events.")    
        
        # Check if the host is hosting an event at the same time
        overlapping_event = await self.repo.get_event_at_same_time(event_data.host_id, event_data.datetime)
        if overlapping_event:   
            raise ValueError(" is already hosting an event at this time.")  
            
        # Check if the event start time is before the end time
        if event_data.start_time >= event_data.end_time:    
            raise ValueError("Event start time must be before the end time.") 


        # TODO: When the below are raised, the client gets a 500 response. refactor to be a 422 or 409

        '''
        # user validations
        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            raise ValueError(" does not exist.")
        
        existing_event = await self.repo.get_event_by_name(event_data.name)
        if existing_event and existing_event.user_id == user_id:
            raise ValueError("Event already exists with this name.")

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
        return await self.repo.create_event(event_data, user_id)

    async def get_event_by_id(self, event_id: uuid.UUID) -> Event:
        # Check if the event exists
        event = await self.repo.get_event_by_id(event_id)
        if not event:
            raise ValueError("Event with the specified ID does not exist.")
        
        return event
    

    async def get_events_by_ids(self, event_ids: list[uuid.UUID]) -> Sequence[Event]:
        return await self.repo.get_events_by_ids(event_ids)

    async def get_event_by_name(self, name: str) -> Event:
        # Check if the event exists
        event = await self.repo.get_event_by_name(name)
        if not event:
            raise ValueError("Event with the specified name does not exist.")
        
        return event
    
    async def get_all_events(self) -> Sequence[Event]:
        return await self.repo.get_all_events()
    
    async def update_event(self, event_id: uuid.UUID, data: EventUpdateSchema) -> Event:
        # Check if the event exists
        event = await self.repo.get_event_by_id(event_id)
        if not event:
            raise ValueError("Event with the specified ID does not exist.")
        
        # Update the event details
        for key, value in data.model_dump(exclude_unset=True).items():
            setattr(event, key, value)
        
        return await self.repo.update_event(event_id, data)

    async def delete_event(self, event_id: uuid.UUID) -> bool:
        # Check if the event exists
        event = await self.repo.get_event_by_id(event_id)
        if not event:
            raise ValueError("Event with the specified ID does not exist.")
        
        return await self.repo.delete_event(event_id)

    async def has_duplicate_event(self, event_data: EventCreateSchema) -> bool:
        # TODO: Implement the logic to check for duplicate events
        return False


    async def join_event_with_user_id(self, x_otp: str, user_id: uuid.UUID) -> UserGrantCreateSchema:
        db_session = self.repo.session
        invite_service = InviteService(db_session)
        user_grant_service = UserGrantService(db_session)

        # Validate the invite
        invite = await invite_service.validate_invite(x_otp)
        event_id = invite.event_id

        # Ensure the user hasn't joined max num of events
        if await user_grant_service.user_hit_limit(user_id): # type: ignore
            logger.warning(f"User {user_id} has hit the maximum event limit.")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User has hit the maximum event limit.")

        grant_data = UserGrantCreateSchema(
            user_id=user_id,
            event_id=event_id,
            access_type="full",
            expires_at=None,
            issued_at=datetime.now(),
            created_from_invite_id=invite.id
        )

        return await user_grant_service.create_user_grant(grant_data) # type: ignore

    async def join_event_with_device_id(self, x_otp: str, device_id: uuid.UUID) -> tuple[DeviceGrant, str]:
        # Create a new instance of InviteService with the same db session used by this service
        db_session = self.repo.session
        invite_service = InviteService(db_session)
        device_grant_service = DeviceGrantService(db_session)

        # Validate the invite
        invite = await invite_service.validate_invite(x_otp)
        event_id = invite.event_id

        if await device_grant_service.device_hit_limit(device_id): # type: ignore
            logger.warning(f"Device {device_id} has hit the maximum event limit.")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device has hit the maximum event limit.")

        grant, token = await device_grant_service.issue_device_grant(event_id, device_id, invite.id) # type: ignore
        return grant, token






async def get_event_service(session: AsyncSession = Depends(get_async_session))-> EventService:
    return EventService(session)

