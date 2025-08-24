from uuid import UUID
from pydantic import BaseModel
from typing import Optional

class EventCreateSchema(BaseModel):
    name: str
    location: str
    datetime: str
    host_id: UUID
    description: str

class EventUpdateSchema(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    datetime: Optional[str] = None
    host_id: Optional[UUID] = None
    description: Optional[str] = None

class EventInviteSchema(BaseModel):
    email: str
    label: str