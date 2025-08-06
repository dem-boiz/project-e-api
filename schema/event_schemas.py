from uuid import UUID
from pydantic import BaseModel
from typing import Optional

class EventCreateSchema(BaseModel):
    name: str | None = None
    location: str | None = None
    datetime: str | None = None
    host_id: UUID
    description: str | None = None

class EventUpdateSchema(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    datetime: Optional[str] = None
    host_id: Optional[UUID] = None
    description: Optional[str] = None
