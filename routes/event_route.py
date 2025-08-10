from fastapi import APIRouter, Depends, status, Security, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from handlers import create_event_handler, delete_event_handler, get_events_handler, patch_event_handler, get_event_by_id_handler, get_event_by_name_handler
from database.session import get_async_session

from services import EventService, AuthService
from repository.event_repository import EventRepository
from schema.event_schemas import EventCreateSchema, EventUpdateSchema
from sqlalchemy.ext.asyncio import AsyncSession
from models import Host

router = APIRouter(prefix="/events", tags=["events"])
security = HTTPBearer()

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
    return await auth_service.get_current_host(token)

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

@router.post("/", status_code=status.HTTP_201_CREATED)
@router.post("", status_code=status.HTTP_201_CREATED)
async def create_event(
    data: EventCreateSchema = Depends(verify_host_authorization), 
    service: EventService = Depends(get_event_service)
):
    """Create a new event - requires authentication and host authorization"""
    return await create_event_handler(data, service)

@router.delete("/{event_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_event(event_id: str, service: EventService = Depends(get_event_service)):
    return await delete_event_handler(service, event_id)

@router.get("/")
@router.get("")
async def get_events(service: EventService = Depends(get_event_service)):
    return await get_events_handler(service) 
@router.get("/get/by-id/{event_id}")
async def get_event_by_id(event_id: str, service: EventService = Depends(get_event_service)):
    return await get_event_by_id_handler(event_id, service)
@router.get("/get/by-name/{name}")
async def get_event_by_name(name: str, service: EventService = Depends(get_event_service)):
    return await get_event_by_name_handler(name, service)


@router.patch("/{event_id}")
async def update_event(event_id: str, data: EventUpdateSchema, service: EventService = Depends(get_event_service)):
    return await patch_event_handler(service, event_id, data)
