from datetime import datetime
from uuid import UUID
from pydantic import BaseModel
from typing import Optional

class EventCreateSchema(BaseModel):
    name: str
    location: str
    datetime: str
    description: str

class EventJoinRequest(BaseModel):
    useAuth: bool

class EventUpdateSchema(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    datetime: Optional[str] = None
    description: Optional[str] = None


class EventReadSchema(BaseModel):
    id: UUID
    name: str
    location: str
    date_time: datetime
    description: Optional[str] = None
    host_id: UUID
    created_at: str
    event_images: list[bytes] = []
    class Config:
        orm_mode = True
        from_attributes = True
        