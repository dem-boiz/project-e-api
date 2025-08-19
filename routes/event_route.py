from fastapi import APIRouter, Depends, status, Security, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from handlers import create_event_handler, delete_event_handler, get_events_handler, patch_event_handler, get_event_by_id_handler, get_event_by_name_handler
from database.session import get_async_session

from services import EventService, AuthService
from repository.event_repository import EventRepository
from schema.event_schemas import EventCreateSchema, EventUpdateSchema
from sqlalchemy.ext.asyncio import AsyncSession
from models import Host
from config.logging_config import get_logger

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

# Dependency to verify host authorization for event deletion
async def verify_event_ownership_for_delete(
    event_id: str,
    current_host: Host = Depends(get_current_host),
    service: EventService = Depends(get_event_service)
) -> str:
    """Verify that the authenticated host owns the event they want to delete"""
    import uuid
    try:
        event_uuid = uuid.UUID(event_id)
        event = await service.get_event_by_id_service(event_uuid)

        if event.host_id != current_host.id:
            logger.warning(f"Host {current_host.id} attempted to delete event {event_id} they do not own.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only delete events that you own"
            )
        return event_id
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid event ID format"
        )
    except Exception as e:
        raise HTTPException(
            status_code=e.status_code if hasattr(e, 'status_code') else status.HTTP_404_NOT_FOUND,
            detail=f"Error occured. {e}"
        )

# Dependency to verify host authorization for event updates
async def verify_event_ownership_for_update(
    event_id: str,
    data: EventUpdateSchema,
    current_host: Host = Depends(get_current_host),
    service: EventService = Depends(get_event_service)
) -> tuple[str, EventUpdateSchema]:
    """Verify that the authenticated host owns the event they want to update"""
    import uuid
    try:
        event_uuid = uuid.UUID(event_id)
        event = await service.get_event_by_id_service(event_uuid)

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
        
        return event_id, data
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid event ID format"
        )
    except Exception as e:
        raise HTTPException(
            status_code=e.status_code if hasattr(e, 'status_code') else status.HTTP_404_NOT_FOUND,
            detail=f"Error occured. {e}"
        )

@router.post("/", status_code=status.HTTP_201_CREATED)
@router.post("", status_code=status.HTTP_201_CREATED)
async def create_event(
    data: EventCreateSchema = Depends(verify_host_authorization), 
    service: EventService = Depends(get_event_service)
):
    """Create a new event - requires authentication and host authorization"""
    logger.info(f"Creating new event: {data.name} for host: {data.host_id}")
    result = await create_event_handler(data, service)
    logger.info(f"Event created successfully: {data.name}")
    return result

@router.delete("/{event_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_event(
    event_id: str = Depends(verify_event_ownership_for_delete),
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

@router.get("/get/by-id/{event_id}")
async def get_event_by_id(event_id: str, service: EventService = Depends(get_event_service)):
    logger.info(f"Fetching event by ID: {event_id}")
    result = await get_event_by_id_handler(event_id, service)
    logger.info(f"Event retrieved by ID: {event_id}")
    return result

@router.get("/get/by-name/{name}")
async def get_event_by_name(name: str, service: EventService = Depends(get_event_service)):
    logger.info(f"Fetching event by name: {name}")
    result = await get_event_by_name_handler(name, service)
    logger.info(f"Event retrieved by name: {name}")
    return result

@router.patch("/{event_id}")
async def update_event(
    event_data: tuple[str, EventUpdateSchema] = Depends(verify_event_ownership_for_update),
    service: EventService = Depends(get_event_service)
):
    """Update an event - requires authentication and ownership verification"""
    event_id, data = event_data
    logger.info(f"Updating event: {event_id}")
    result = await patch_event_handler(service, event_id, data)
    logger.info(f"Event updated successfully: {event_id}")
    return result
