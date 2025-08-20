from schema import EventCreateSchema, EventUpdateSchema
from services import EventService 

async def create_event_handler(data: EventCreateSchema, service: EventService):
    return await service.create_event_service(data)

async def get_events_handler(service: EventService):
    return await service.get_all_events_service()

async def delete_event_handler(service: EventService, event_id: str):
    return await service.delete_event_service(event_id)

async def patch_event_handler(service: EventService, event_id: str, data: EventUpdateSchema):
    return await service.update_event_service(event_id, data)

async def get_event_by_id_handler(event_id: str, service: EventService):
    return await service.get_event_by_id_service(event_id)

async def get_event_by_name_handler(name: str, service: EventService):
    return await service.get_event_by_name_service(name)

async def join_event_handler(otp: str, service: EventService):
    return await service.join_event(otp)