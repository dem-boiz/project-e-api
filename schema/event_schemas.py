from uuid import UUID
from pydantic import BaseModel

class EventCreateSchema(BaseModel):
    name: str
    location: str | None = None
    datetime: str
    host_id: UUID
    description: str | None = None
