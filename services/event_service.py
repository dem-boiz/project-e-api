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
from schema.event_schemas import EventReadSchema, GuestReadSchema
from schema.invite_schemas import InviteUpdateRequest
from schema.user_grant_schemas import UserGrantCreateSchema, UserGrantReadSchema
from schema.user_schemas import UserReadSchema
from services.device_grant_service import DeviceGrantService
from services.invite_service import InviteService
from services.user_grant_service import UserGrantService


#TODO: add logging


logger = get_logger("api.events")
class EventService:
    def __init__(self, db: AsyncSession):
        self.repo = EventRepository(db)
        self.user_repo = UserRepository(db)
    async def create_event(self, event_data: EventCreateSchema, user_id: uuid.UUID) -> EventReadSchema:

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
        if existing_event and existing_event.host_id == user_id:
            raise ValueError("Event already exists with this name.")

        # Check if the event date is in the past
        event_datetime = datetime.fromisoformat(event_data.date_time)
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

    async def get_event_by_id(self, event_id: uuid.UUID) -> EventReadSchema:
        # Check if the event exists
        event = await self.repo.get_event_by_id(event_id)
        if not event:
            raise ValueError("Event with the specified ID does not exist.")
        
        return event

    async def get_events_by_ids(self, event_ids: list[uuid.UUID]) -> Sequence[EventReadSchema]:
        return await self.repo.get_events_by_ids(event_ids)

    async def get_event_by_name(self, name: str) -> EventReadSchema | None:
        # Check if the event exists
        event = await self.repo.get_event_by_name(name)
        if not event:
            raise ValueError("Event with the specified name does not exist.")
        
        return event

    async def get_all_events(self) -> Sequence[EventReadSchema]:
        return await self.repo.get_all_events()
    
    async def get_accessible_events_for_user(
            self, 
            user: UserReadSchema | None = None,
            device_id: uuid.UUID | None = None,
            cookies: dict | None = None
    ) -> list[EventReadSchema]:
        accessible_events: list[EventReadSchema] = []
        """ Returns the all accessible events for a user based on their user ID and/or device ID."""
        if user:
            user_grant_service = UserGrantService(self.repo.session)
            user_grants = await user_grant_service.get_active_grants_by_user_id(user.id)  # type: ignore
            event_ids = [grant.event_id for grant in user_grants]
            events = await self.get_events_by_ids(event_ids)
            logger.debug(f"User {user.id} has access to events: {event_ids}... a total of {len(event_ids)} events.")
            events_hosted_by_user = await self.repo.get_events_hosted_by_user(user.id)
            accessible_events.extend(events)
            accessible_events.extend(events_hosted_by_user)
        if device_id:
            device_grant_service = DeviceGrantService(self.repo.session)
            event_ids_from_cookies = await self.get_valid_event_ids_from_device_cookies(device_grant_service, cookies)
            accessible_events_from_cookies = await self.get_events_by_ids(event_ids_from_cookies)
            logger.debug(f"Device {device_id} has access to events: {event_ids_from_cookies}... a total of {len(event_ids_from_cookies)} events.")
            accessible_events.extend(accessible_events_from_cookies)





        if not user and not device_id:
            logger.debug("No user or device ID provided, returning empty event list.")
            return []
        non_duplicate_events = list({event.id: event for event in accessible_events}.values())  # Remove duplicates while preserving order


        return non_duplicate_events

    async def get_valid_event_ids_from_device_cookies(
            self, 
            device_grant_service: DeviceGrantService, 
            cookies: dict | None
    ) -> list[uuid.UUID]:
        """ Extract valid event IDs from cookies by validating each event access token. """
        valid_event_ids = []
        if not cookies:
            return valid_event_ids
        
        for cookie in cookies:
            if cookie.startswith("event_") and cookie.endswith("_token"):
                event_id = cookie[len("event_"):-len("_token")]
                try:
                    uuid_event_id = uuid.UUID(event_id)
                except ValueError:
                    logger.warning(f"Invalid event ID in cookie: {event_id}")
                    continue

                if await device_grant_service.validate_device_token(cookies[cookie], uuid_event_id): # type: ignore
                    valid_event_ids.append(uuid_event_id)
                    logger.debug(f"Valid event ID from cookie: {event_id}")
        return valid_event_ids

    async def update_event(self, event_id: uuid.UUID, data: EventUpdateSchema) -> EventReadSchema | None:
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




    async def get_event_vendors(self, event_id: uuid.UUID) -> list[GuestReadSchema]:
        """Retrieve all vendors (both user and device based) for a specific event."""
        vendors = []
        # First we get all user grants for the event
        user_grant_service = UserGrantService(self.repo.session)
        user_grants = await user_grant_service.get_active_grants_for_event(event_id)  # type: ignore

        for grant in user_grants:
            if grant.user_id is None:
                logger.warning(f"UserGrant {grant.id} has no associated user_id.")
                continue
            if grant.user_id is not None:
                user_data = await self.user_repo.get_user_by_id(grant.user_id)
                if user_data and grant.access_type == "vendor":
                    vendors.append(GuestReadSchema(
                        id=grant.user_id,
                        name=user_data.name,
                        email=user_data.email,
                        type="user"
                    ))


        # Now we get all device grants for the event
        device_grant_service = DeviceGrantService(self.repo.session)
        device_grants = await device_grant_service.get_active_grants_for_event(event_id)  # type: ignore
        for device_grant in device_grants:
            vendors.append(GuestReadSchema(
                id=device_grant.device_id,
                name=device_grant.label,
                type="device"
            ))

        return vendors


    async def get_event_guests(self, event_id: uuid.UUID) -> list[GuestReadSchema]:
        """Retrieve all guests (both user and device based) for a specific event."""
        guests = []
        # First we get all user grants for the event
        user_grant_service = UserGrantService(self.repo.session)
        user_grants = await user_grant_service.get_active_grants_for_event(event_id)  # type: ignore
        user_ids = [grant.user_id for grant in user_grants if grant.user_id is not None]

        for grant in user_grants:
            if grant.user_id is None:
                logger.warning(f"UserGrant {grant.id} has no associated user_id.")
                continue
            if grant.user_id is not None:
                user_data = await self.user_repo.get_user_by_id(grant.user_id)
                if user_data and grant.access_type is "guest":
                    guests.append(GuestReadSchema(
                        id=grant.user_id,
                        name=user_data.name,
                        email=user_data.email,
                        type="user"
                    ))


        # Now we get all device grants for the event
        device_grant_service = DeviceGrantService(self.repo.session)
        device_grants = await device_grant_service.get_active_grants_for_event(event_id)  # type: ignore
        for device_grant in device_grants:
            guests.append(GuestReadSchema(
                id=device_grant.device_id,
                name=device_grant.label,
                type="device"
            ))

        return guests

    async def join_event_with_user_id(self, x_otp: str, user_id: uuid.UUID) -> UserGrantReadSchema:
        db_session = self.repo.session
        invite_service = InviteService(db_session)
        user_grant_service = UserGrantService(db_session)

        # Validate the invite
        invite = await invite_service.validate_invite(x_otp)
        event = await self.repo.get_event_by_id(invite.event_id)

        event_id = invite.event_id

        # Ensure the user hasn't joined max num of events
        if await user_grant_service.user_hit_limit(user_id): # type: ignore
            logger.warning(f"User {user_id} has hit the maximum event limit.")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User has hit the maximum event limit.")


        if event and event.host_id == user_id:
            logger.warning(f"User {user_id} is the host of event {event_id} and cannot join as a guest.")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Event host cannot join their own event.")
        
        grant_data = UserGrantCreateSchema(
            user_id=user_id,
            event_id=event_id,
            access_type="guest" if invite.type == "guest" else "vendor",
            expires_at=None,
            issued_at=datetime.now(),
            created_from_invite_id=invite.id
        )
        
        update_data = InviteUpdateRequest(used_at=datetime.now())
        await invite_service.update_pending_invite_by_event_id(update_data, event_id, invite.id)
        user_grant = await user_grant_service.create_user_grant(grant_data) # type: ignore
        return user_grant

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

        grant, token = await device_grant_service.issue_device_grant(
            event_id,
            device_id,
            invite.id,
            invite.email if invite.email else invite.label
        ) # type: ignore


        update_data = InviteUpdateRequest(used_at=datetime.now())
        await invite_service.update_pending_invite_by_event_id(update_data, event_id, invite.id)

        return grant, token

    async def remove_guest_from_event(self, event_id: uuid.UUID, guest_id: uuid.UUID, type: str) -> None:
        db_session = self.repo.session

        if type == "user":
            logger.info(f"Removing user guest {guest_id} from event {event_id}")
            user_grant_service = UserGrantService(db_session)
            await user_grant_service.revoke_user_grant(guest_id, event_id)
            logger.info(f"Removed user guest {guest_id} from event {event_id}")
        elif type == "device":
            logger.info(f"Removing device guest {guest_id} from event {event_id}")
            device_grant_service = DeviceGrantService(db_session)
            await device_grant_service.revoke_device_grant(guest_id, event_id)
            logger.info(f"Removed device guest {guest_id} from event {event_id}")
        else:
            logger.error(f"Invalid guest type provided: {type}")
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid guest type.")


