import uuid
from fastapi import APIRouter, Depends, Response, status, Request
from fastapi.security import HTTPBearer
from handlers import (
    create_event_handler, 
    delete_event_handler, 
    get_events_handler, 
    patch_event_handler, 
    get_event_guests_handler,
    get_event_pending_invites_handler,
    get_my_events_handler,
    join_event_handler,
    delete_event_pending_invite_handler
)               


from services.invite_service import InviteService, get_invite_service
from services.event_service import EventService, get_event_service

from handlers.event_handler import create_event_invite_handler, update_pending_event_invite_handler
from schema.invite_schemas import InviteCreateRequest, InviteUpdateRequest, InviteCreateResponse
from services import EventService, InviteService
from services.auth_service import (
    get_current_user, 
    get_current_user_graceful,
    validate_token_parent_session,
    verify_event_ownership,
    get_device_id
)
from schema import EventCreateSchema, EventUpdateSchema
from models import User
from config.logging_config import get_logger

import uuid
# Initialize logger
logger = get_logger("api.events")

router = APIRouter(prefix="/events", tags=["events"])

# Note: HttpBearer automatically checks for the existence of a token but does not validate it. 
security = HTTPBearer()


@router.post("/", status_code=status.HTTP_201_CREATED, dependencies=[Depends(validate_token_parent_session)])
@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(validate_token_parent_session)])
async def create_event(
    data: EventCreateSchema,
    user: User = Depends(get_current_user),
    service: EventService = Depends(get_event_service)
):
    """Create a new event - requires authentication and user authorization"""
    logger.info(f"Creating new event: {data.name} for user: {user.id}")
    result = await create_event_handler(data, service, user.id)
    logger.info(f"Event created successfully: {data.name}")
    return result

@router.delete("/{event_id}", 
    status_code=status.HTTP_204_NO_CONTENT, 
    dependencies=[
        Depends(validate_token_parent_session),
        Depends(verify_event_ownership)
    ]
)
async def delete_event(
    event_id: uuid.UUID,
    service: EventService = Depends(get_event_service)
):
    """Delete an event - requires authentication and ownership verification"""
    logger.info(f"Deleting event: {event_id}")
    result = await delete_event_handler(service, event_id)
    logger.info(f"Event deleted successfully: {event_id}")
    return result

@router.get("/")
@router.get("")
async def get_events(service: EventService = Depends(get_event_service)):
    logger.info("Fetching all events")
    result = await get_events_handler(service)
    logger.info(f"Retrieved {len(result) if isinstance(result, list) else 'unknown count'} events")
    return result

@router.patch("/{event_id}", 
    status_code=status.HTTP_204_NO_CONTENT, 
    dependencies=[
        Depends(validate_token_parent_session),
        Depends(verify_event_ownership)
    ]
)
async def update_event(
    data: EventUpdateSchema,
    event_id: uuid.UUID,
    service: EventService = Depends(get_event_service)
):
    """Update an event - requires authentication and ownership verification"""
    logger.info(f"Updating event: {event_id}")
    result = await patch_event_handler(service, event_id, data)
    logger.info(f"Event updated successfully: {event_id}")
    return result


# TODO: Update to also allow vendors to create invites
@router.post("/{event_id}/invite")
async def post_event_invite(
    data: InviteCreateRequest,
    verification_data: tuple[uuid.UUID, User] = Depends(verify_event_ownership),
    service: InviteService = Depends(get_invite_service),
) -> InviteCreateResponse:
    """Create and return the invite code for an event - requires authentication and ownership verification"""
    event_id, user = verification_data
    logger.info(f"Creating invite for event: {event_id}")
    # Build InviteCreateRequest from EventInviteSchema and event_id
    result = await create_event_invite_handler(data, event_id, user.id, service)
    logger.info(f"Created invite for event: {event_id}")
    return result

@router.patch("/{event_id}/invites/pending/{invite_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(validate_token_parent_session),
        Depends(verify_event_ownership)
    ]
)
async def update_event_invite(
    event_id: uuid.UUID,
    invite_id: uuid.UUID,
    data: InviteUpdateRequest,
    service: InviteService = Depends(get_invite_service),
):
    """Update an existing invite for an event - requires authentication and ownership verification"""
    logger.info(f"Updating invite {invite_id} for event: {event_id}")
    await update_pending_event_invite_handler(data, event_id, invite_id, service)
    logger.info(f"Updated invite {invite_id} for event: {event_id}")
    return



@router.post("/join/{otp}")
async def join_event(
    otp: str,
    response: Response,
    request: Request,
    service: EventService = Depends(get_event_service),
    device_id: uuid.UUID | None = Depends(get_device_id),
    user: User | None = Depends(get_current_user_graceful)
):
    """Join an event - requires authentication and event existence verification"""
    logger.info(f"Joining event with otp: {otp}")
    request_body = await request.json()
    use_auth = request_body.get("useAuth", False)
    logger.debug(f"Request body: {request_body}, useAuth: {use_auth}")
    result = await join_event_handler(
        otp, 
        service,
        device_id=device_id, # type: ignore
        response=response,
        user=user,
        use_auth=use_auth
    )
    return result

# TODO: Account for max guests in all invite operations

@router.get("/{event_id}/invites/pending", 
    dependencies=[
        Depends(validate_token_parent_session), 
        Depends(verify_event_ownership)
    ]
)
async def get_event_pending_invites(
    event_id: uuid.UUID,
    service: InviteService = Depends(get_invite_service)
):
    """Get all pending invites for a specific event - requires authentication and event existence verification"""
    logger.info(f"Fetching pending invites for event: {event_id}")
    result = await get_event_pending_invites_handler(event_id, service)
    logger.debug(f'Pending invites for event right before response {event_id}: {result}')
    logger.info(f"Retrieved {len(result) if isinstance(result, list) else 'unknown count'} pending invites for event: {event_id}")
    return result


@router.delete("/{event_id}/invites/pending/{invite_id}", dependencies=[
    Depends(validate_token_parent_session),
    Depends(verify_event_ownership)
])
async def delete_event_pending_invite(
    event_id: uuid.UUID,
    invite_id: uuid.UUID,
    service: InviteService = Depends(get_invite_service)
):
    """Delete a pending invite for a specific event - requires authentication and event existence verification"""
    logger.info(f"Deleting pending invite {invite_id} for event: {event_id}")
    result = await delete_event_pending_invite_handler(event_id, invite_id, service)
    logger.info(f"Deleted {len(result) if isinstance(result, list) else 'unknown count'} pending invites for event: {event_id}")
    return result


@router.get("/{event_id}/guests", 
    dependencies=[
        Depends(validate_token_parent_session), 
        Depends(verify_event_ownership)
    ]
)
async def get_event_guests(
    event_id: uuid.UUID,
    service: InviteService = Depends(get_invite_service)
):
    """Get all guests for a specific event - requires authentication and event existence verification"""
    logger.info(f"Fetching guests for event: {event_id}")
    result = await get_event_guests_handler(event_id, service)
    logger.info(f"Retrieved {len(result) if isinstance(result, list) else 'unknown count'} guests for event: {event_id}")
    return result

@router.get("/my-events")
async def get_my_events(
    request: Request,
    service: EventService = Depends(get_event_service)
):
    """Get all events for the current user - requires authentication"""
    logger.info("Fetching events for current user")
    result = await get_my_events_handler(request.cookies, service)
    logger.info(f"Retrieved {len(result) if isinstance(result, list) else 'unknown count'} events for user")
    return result
