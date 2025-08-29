from uuid import UUID
from pydantic import BaseModel
from typing import Optional

class EventCreateSchema(BaseModel):
    name: str
    location: str
    datetime: str
    description: str

class EventUpdateSchema(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    datetime: Optional[str] = None
    description: Optional[str] = None
