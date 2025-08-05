from pydantic import BaseModel, EmailStr
import uuid
from datetime import datetime
from typing import Optional
 
class OTPVerifyResponse(BaseModel):
    success: bool
    message: str

class OTPCreateRequest(BaseModel):
    email: EmailStr
    event_id: uuid.UUID

class OTPVerifyRequest(BaseModel):
    otp_code: str
    email: EmailStr
    event_id: uuid.UUID
 

class OTPResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    event_id: uuid.UUID
    otp_code: str
    expires_at: datetime
    used: bool
    created_at: datetime

    class Config:
        from_attributes = True
 
class OTPDeleteRequest(BaseModel):
    otp_code: str