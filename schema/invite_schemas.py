from pydantic import BaseModel, EmailStr
import uuid
from datetime import datetime
from typing import Optional
 

class InviteCreateRequest(BaseModel):
    email: Optional[EmailStr] = None
    label: Optional[str] = None
    access_type: str
    delivery_method: str
class InviteCreateResponse(BaseModel):
    id: uuid.UUID
    email: Optional[EmailStr] = None
    event_id: uuid.UUID
    expires_at: datetime
    created_at: datetime
    invite_link: Optional[str] = None
    label: Optional[str] = None
    class Config:
        from_attributes = True
 
class InviteDeleteRequest(BaseModel):
    id: uuid.UUID


class InviteUpdateRequest(BaseModel):
    label: Optional[str] = None
    access_type: Optional[str] = None
    used_at: Optional[datetime] = None
