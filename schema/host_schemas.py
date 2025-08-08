from uuid import UUID
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class HostCreateSchema(BaseModel): 
    company_name: str
    email: EmailStr # ISO format date string
    password: str 
    created_at: datetime  # ISO format date string // Do we need created_at fields here and below?

class HostUpdateSchema(BaseModel):
    email: Optional[EmailStr] = None
    company_name: Optional[str] = None
    password: Optional[str] = None
    created_at: Optional[datetime] = None

# Schema used for reading/returning a host (e.g., in responses) // ??
class HostReadSchema(BaseModel):
    id: UUID
    host_number: int
    password_hash: str
    created_at: datetime 
    company_name: str
    email: EmailStr
    class Config:
        from_attributes = True 