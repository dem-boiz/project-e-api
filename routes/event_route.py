from fastapi import APIRouter, Depends, status
from handlers import create_event_handler, delete_event_handler, get_events_handler, patch_event_handler, get_event_by_id_handler, get_event_by_name_handler
from database.session import get_async_session

from services import EventService
from repository.event_repository import EventRepository
from schema.event_schemas import EventCreateSchema, EventUpdateSchema
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/events", tags=["events"])

# Dependency to get EventService
async def get_event_service(session: AsyncSession = Depends(get_async_session))-> EventService:
    return EventService(session)

@router.post("/", status_code=status.HTTP_201_CREATED)
@router.post("", status_code=status.HTTP_201_CREATED)
async def create_event(data: EventCreateSchema, service: EventService = Depends(get_event_service)):
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
