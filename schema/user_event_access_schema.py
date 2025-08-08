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
    otp_id: UUID  # Optional field for OTP ID
    is_deleted: bool = False
    
    class Config:
        from_attributes = True

class UserEventAccessReadSchema(BaseModel):
    user_id: UUID
    event_id: UUID
    otp_id: UUID  # OTP ID can be optional in read schema
    is_deleted: bool
    granted_at: datetime

    class Config:
        from_attributes = True

class UserEventAccessUpdateSchema(BaseModel):
    otp_id: Optional[UUID] = None  # Allow updating OTP ID
    is_deleted: Optional[bool] = None
    granted_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class UserEventAccessDeleteSchema(BaseModel):
    user_id: UUID
    event_id: UUID

    class Config:
        from_attributes = True