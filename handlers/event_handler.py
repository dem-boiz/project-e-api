import os
import uuid
from fastapi import Response
from schema import EventCreateSchema, EventUpdateSchema
from schema.invite_schemas import InviteCreateRequest
from services import EventService, DeviceGrantService
from config.logging_config import get_logger
from services.invite_service import InviteService


IS_PROD = os.getenv("ENV") == "PROD"

logger = get_logger("api.events")   

async def create_event_handler(data: EventCreateSchema, service: EventService, host_id: uuid.UUID):
    return await service.create_event(data, host_id)

async def get_events_handler(service: EventService):
    return await service.get_all_events()

async def delete_event_handler(service: EventService, event_id: uuid.UUID):
    return await service.delete_event(event_id)

async def patch_event_handler(service: EventService, event_id: uuid.UUID, data: EventUpdateSchema):
    return await service.update_event(event_id, data)

async def get_event_by_id_handler(event_id: uuid.UUID, service: EventService):
    return await service.get_event_by_id(event_id)

async def get_event_by_name_handler(name: str, service: EventService):
    return await service.get_event_by_name(name)

async def get_event_pending_invites_handler(event_id: uuid.UUID, service: InviteService):
    return await service.get_pending_invites_by_event(event_id)

async def join_event_handler(otp: str, service: EventService, device_id: uuid.UUID, response: Response):
    grant, token = await service.join_event(otp, device_id)

    cookieName = f'event_{grant.event_id}_token'
    response.set_cookie(
        key=cookieName, 
        value=token,
        path='/',
        httponly=True,
        secure=IS_PROD,
        samesite="lax",
        max_age=30*24*3600  # 30 days
    )

    return {"message": "Joined event successfully"}

async def get_my_events_handler(cookies: dict, service: EventService):
    event_ids = []
    for key, value in cookies.items():
        if key.startswith("event_") and key.endswith("_token"):
            # parse event id from cookie name (format is event_<event_id>_token)
            event_id = key[len("event_"):-len("_token")]

            # This is a an event access cookie, we validate the token by using it to retrieve
            # the associated device grant and checking its validity
            # The device grant is then returned.
            if await DeviceGrantService.validate_device_token(value, event_id): # type: ignore
                event_ids.append(event_id)

    if not event_ids:
        logger.warning("No valid event IDs found in cookies")
        return []
    
    logger.debug(f"Found a total of {len(event_ids)} event IDs in cookies")
    event_info = await service.get_events_by_ids(event_ids)

    return event_info

async def get_event_guests_handler(event_id: uuid.UUID, service: InviteService):
    ''' Implement this '''
    return

async def create_event_invite_handler(invite_data: InviteCreateRequest, event_id: uuid.UUID, host_id: uuid.UUID, service: InviteService):
    invite = await service.create_invite(invite_data, event_id, host_id)
    # Convert to dict and remove sensitive field
    invite_dict = invite.__dict__
    invite_dict.pop('otp_code', None)
    return invite_dict

    


async def delete_event_pending_invite_handler(event_id: uuid.UUID, invite_id: uuid.UUID, service: InviteService):
    return await service.delete_pending_invite(event_id, invite_id)
