from pydantic import BaseModel, EmailStr
import uuid
from datetime import datetime
from typing import Optional
 

class InviteCreateRequest(BaseModel):
    email: Optional[EmailStr] = None
    label: Optional[str] = None
    type: str

class InviteCreateResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    event_id: uuid.UUID
    otp_code: str
    expires_at: datetime
    used: bool
    created_at: datetime

    class Config:
        from_attributes = True
 
class InviteDeleteRequest(BaseModel):
    id: uuid.UUID