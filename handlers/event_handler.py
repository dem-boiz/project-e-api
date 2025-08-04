from schema.event_schemas import EventCreateSchema
from repository.event_repository import EventRepository

async def post_event_handler(repo: EventRepository, data: EventCreateSchema):
    return await repo.create_event(data)

async def get_events_handler(repo: EventRepository):
    return await repo.get_all_events()

async def delete_event_handler(repo: EventRepository, event_id: str):
    return await repo.delete_event(event_id)

async def patch_event_handler(repo: EventRepository, event_id: str, data: EventCreateSchema):
    return await repo.update_event(event_id, data)

