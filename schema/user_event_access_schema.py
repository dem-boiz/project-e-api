from pydantic import BaseModel, EmailStr
from uuid import UUID
from datetime import datetime
from typing import Optional

class UserEventAccessSearchSchema(BaseModel):
    email: EmailStr

    class Config:
        from_attributes = True

class UserEventAccessCreateSchema(BaseModel):
    user_id: UUID
    event_id: UUID
    invite_id: UUID
    revoked_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class UserEventAccessReadSchema(BaseModel):
    user_id: UUID
    event_id: UUID
    invite_id: UUID  # Invite ID can be optional in read schema
    revoked_at: datetime
    granted_at: datetime

    class Config:
        from_attributes = True

class UserEventAccessUpdateSchema(BaseModel):
    invite_id: Optional[UUID] = None  # Allow updating Invite ID
    revoked_at: Optional[datetime] = None
    granted_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class UserEventAccessDeleteSchema(BaseModel):
    user_id: UUID
    event_id: UUID

    class Config:
        from_attributes = True