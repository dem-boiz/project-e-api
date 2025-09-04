from pydantic import BaseModel
from uuid import UUID
from datetime import datetime
from typing import Optional



class UserGrantReadSchema(BaseModel):
    id: UUID
    user_id: UUID
    event_id: UUID
    access_type: str
    expires_at: Optional[datetime] = None
    issued_at: datetime
    revoked_at: Optional[datetime] = None
    created_from_invite_id: UUID
    class Config:
        from_attributes = True


class UserGrantSearchSchema(BaseModel):
    user_id: Optional[UUID] = None
    event_id: Optional[UUID] = None
    access_type: Optional[str] = None
    active_only: bool = True
    class Config:
        from_attributes = True


class UserGrantCreateSchema(BaseModel):
    user_id: UUID
    event_id: UUID
    access_type: str
    expires_at: Optional[datetime] = None
    issued_at: datetime
    created_from_invite_id: UUID
    
    class Config:
        from_attributes = True

class UserGrantUpdateSchema(BaseModel):
    revoked_at: Optional[datetime] = None
    class Config:
        from_attributes = True

class UserGrantDeleteSchema(BaseModel):
    user_id: UUID
    event_id: UUID
    class Config:
        from_attributes = True