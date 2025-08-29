from fastapi import APIRouter, Depends, Response, status, Security, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from handlers import (
    create_event_handler, 
    delete_event_handler, 
    get_events_handler, 
    patch_event_handler, 
    get_event_by_id_handler, 
    get_event_by_name_handler,
    get_my_events_handler,
    join_event_handler
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

# Dependency to verify host authorization for event creation
async def verify_host_authorization(
    data: EventCreateSchema,
    current_host: Host = Depends(get_current_host)
) -> EventCreateSchema:
    """Verify that the authenticated host matches the host_id in the request"""
    if current_host.id != data.host_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only create events for your own host account"
        )
    return data


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


# Dependency to verify host authorization for event deletion
async def verify_event_ownership_for_delete(
    event_id: uuid.UUID,
    current_host: Host = Depends(get_current_host),
    service: EventService = Depends(get_event_service)
) -> uuid.UUID:
    """Verify that the authenticated host owns the event they want to delete"""
    try:
        event = await service.get_event_by_id(event_id=event_id)

        if event.host_id != current_host.id:
            logger.warning(f"Host {current_host.id} attempted to delete event {event_id} they do not own.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only delete events that you own"
            )
        return event_id
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=getattr(e, 'status_code', status.HTTP_404_NOT_FOUND),
            detail=f"Error occured. {e}"
        )

# Dependency to verify host authorization for event updates
async def verify_event_ownership_for_modification(
    event_id: uuid.UUID,
    data: EventUpdateSchema,
    current_host: Host = Depends(get_current_host),
    service: EventService = Depends(get_event_service)
) -> tuple[uuid.UUID, EventUpdateSchema, Host]:
    """Verify that the authenticated host owns the event they want to update"""
    try:
        event = await service.get_event_by_id(event_id=event_id)

        if event.host_id != current_host.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only update events that you own"
            )
        
        # If the update data includes a host_id, ensure it matches the current host
        if data.host_id is not None and data.host_id != current_host.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You cannot change the host of an event to a different host"
            )
        
        return event_id, data, current_host
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
    data: EventCreateSchema = Depends(verify_host_authorization), 
    service: EventService = Depends(get_event_service)
):
    """Create a new event - requires authentication and host authorization"""
    logger.info(f"Creating new event: {data.name} for host: {data.host_id}")
    result = await create_event_handler(data, service)
    logger.info(f"Event created successfully: {data.name}") 
    return result

@router.delete("/{event_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(validate_token_parent_session)])
async def delete_event(
    event_id: uuid.UUID = Depends(verify_event_ownership_for_modification),
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

@router.patch("/{event_id}", status_code=204, dependencies=[Depends(validate_token_parent_session)])
async def update_event(
    event_data: tuple[uuid.UUID, EventUpdateSchema, Host] = Depends(verify_event_ownership_for_modification),
    service: EventService = Depends(get_event_service)
):
    """Update an event - requires authentication and ownership verification"""
    event_id, data, get_current_host = event_data
    logger.info(f"Updating event: {event_id}")
    result = await patch_event_handler(service, event_id, data)
    logger.info(f"Event updated successfully: {event_id}")
    return result


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
