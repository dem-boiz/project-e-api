from datetime import datetime
from uuid import UUID
from pydantic import BaseModel
from typing import Optional
    
class EventCreateSchema(BaseModel):
    name: str
    location: str
    date_time: str
    description: str

class EventJoinRequest(BaseModel):
    useAuth: bool

class EventUpdateSchema(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    date_time: Optional[str] = None
    description: Optional[str] = None


class GuestReadSchema(BaseModel):
    id: UUID
    name: str
    email: Optional[str] = None
    type: str
    class Config:
        orm_mode = True
        from_attributes = True

class EventReadSchema(BaseModel):
    id: UUID
    name: str
    location: str
    date_time: datetime
    description: Optional[str] = None
    host_id: UUID
    created_at: datetime
    event_images: list[bytes] = []
    class Config:
        orm_mode = True
        from_attributes = True
        