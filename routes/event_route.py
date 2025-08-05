from fastapi import APIRouter, Depends, status
from handlers.event_handler import post_event_handler, delete_event_handler, get_events_handler, patch_event_handler
from database.session import get_async_session

from repository.event_repository import EventRepository
from schema.event_schemas import EventCreateSchema, EventUpdateSchema
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/events", tags=["events"])

async def get_event_repo(session: AsyncSession = Depends(get_async_session)):
    return EventRepository(session)

@router.post("/", status_code=status.HTTP_201_CREATED)
@router.post("", status_code=status.HTTP_201_CREATED)
async def create_event(data: EventCreateSchema, repo: EventRepository = Depends(get_event_repo)):
    return await post_event_handler(repo, data)

@router.delete("/{event_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_event(event_id: str, repo: EventRepository = Depends(get_event_repo)):
    return await delete_event_handler(repo, event_id)

@router.get("/")
@router.get("")
async def get_events(repo: EventRepository = Depends(get_event_repo)):
    return await get_events_handler(repo)

@router.patch("/{event_id}")
async def update_event(event_id: str, data: EventUpdateSchema, repo: EventRepository = Depends(get_event_repo)):
    return await patch_event_handler(repo, event_id, data)
