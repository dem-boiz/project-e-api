from pydantic import BaseModel, EmailStr
from uuid import UUID
from datetime import datetime
from typing import Optional

class UserGrantSearchSchema(BaseModel):
    email: EmailStr

    class Config:
        from_attributes = True

class UserGrantCreateSchema(BaseModel):
    user_id: UUID
    event_id: UUID
    invite_id: UUID
    revoked_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class UserGrantReadSchema(BaseModel):
    user_id: UUID
    event_id: UUID
    invite_id: UUID  # Invite ID can be optional in read schema
    revoked_at: datetime
    granted_at: datetime

    class Config:
        from_attributes = True

class UserGrantUpdateSchema(BaseModel):
    invite_id: Optional[UUID] = None  # Allow updating Invite ID
    revoked_at: Optional[datetime] = None
    granted_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class UserGrantDeleteSchema(BaseModel):
    user_id: UUID
    event_id: UUID

    class Config:
        from_attributes = True