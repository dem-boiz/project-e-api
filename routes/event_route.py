from datetime import datetime
from fastapi import APIRouter, Depends, Response, status, Security, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
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
from database.session import get_async_session

from handlers.event_handler import create_event_invite_handler
from schema.invite_schemas import InviteCreateRequest
from services import EventService, AuthService, InviteService
from schema import EventCreateSchema, EventUpdateSchema
from sqlalchemy.ext.asyncio import AsyncSession
from models import Host
from config.logging_config import get_logger
 
import uuid
# Initialize logger
logger = get_logger("api.events")

router = APIRouter(prefix="/events", tags=["events"])

# Note: HttpBearer automatically checks for the existence of a token but does not validate it. 
security = HTTPBearer()

# TODO: Move these dependencies to a separate file

# Dependency to get EventService
async def get_event_service(session: AsyncSession = Depends(get_async_session))-> EventService:
    return EventService(session)

# Dependency to get AuthService for authentication
async def get_auth_service(session: AsyncSession = Depends(get_async_session)) -> AuthService:
    return AuthService(session)

async def get_invite_service(session: AsyncSession = Depends(get_async_session)) -> InviteService:
    return InviteService(session)

# Dependency to get current authenticated host
async def get_current_host(
    credentials: HTTPAuthorizationCredentials = Security(security),
    auth_service: AuthService = Depends(get_auth_service)
) -> Host:
    """Get the current authenticated host from JWT token"""
    token = credentials.credentials
    return await auth_service.get_current_host_service(token)

async def validate_token_parent_session(
    credentials: HTTPAuthorizationCredentials = Security(security),
    auth_service: AuthService = Depends(get_auth_service)
): 
    """ validate token parent session by checking that it hasnt been revoked"""
    isActive = await auth_service.validate_session_is_active(credentials.credentials)

    if isActive == False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="session expired"
        )
    
    return 

# Dependency to verify event ownership. unlike the previous one, this one does not require the update data.
# TODO: Replace all usage of above method to use this one instead? 
async def verify_event_ownership(
    event_id: uuid.UUID,
    current_host: Host = Depends(get_current_host),
    service: EventService = Depends(get_event_service)
) -> tuple[uuid.UUID, Host]:
    """Verify that the authenticated host owns the event"""
    try:
        event = await service.get_event_by_id(event_id=event_id)

        if event.host_id != current_host.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only update events that you own"
            )
    
        return event_id, current_host
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid event ID format"
        )
    except Exception as e:
        raise HTTPException(
            status_code=getattr(e, 'status_code', status.HTTP_404_NOT_FOUND),
            detail=f"Error occured. {e}"
        )


@router.post("/", status_code=status.HTTP_201_CREATED, dependencies=[Depends(validate_token_parent_session)])
@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(validate_token_parent_session)])
async def create_event(
    data: EventCreateSchema,
    host: Host = Depends(get_current_host),
    service: EventService = Depends(get_event_service)
):
    """Create a new event - requires authentication and host authorization"""
    logger.info(f"Creating new event: {data.name} for host: {host.id}")
    result = await create_event_handler(data, service, host.id)
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
    status_code=204, 
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
    verification_data: tuple[uuid.UUID, Host] = Depends(verify_event_ownership),
    service: InviteService = Depends(get_invite_service),
):
    """Create and return the invite code for an event - requires authentication and ownership verification"""
    event_id, host = verification_data
    logger.info(f"Creating invite for event: {event_id}")
    # Build InviteCreateRequest from EventInviteSchema and event_id
    result = await create_event_invite_handler(data, event_id, host.id, service)
    logger.info(f"Created invite for event: {event_id}")
    return result

@router.post("/join/{otp}")
async def join_event(
    otp: str,
    response: Response,
    service: EventService = Depends(get_event_service)
):
    """Join an event - requires authentication and event existence verification"""
    logger.info(f"Joining event with otp: {otp}")
    
    result = await join_event_handler(
        otp, 
        service,
        device_id="THIS IS A TEST DEVICE ID", # type: ignore
        response=response
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
