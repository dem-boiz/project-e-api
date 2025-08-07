from uuid import UUID
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class HostCreateSchema(BaseModel): 
    company_name: str
    email: EmailStr # ISO format date string
    password_hash: str 
    created_at: datetime  # ISO format date string

class HostUpdateSchema(BaseModel):
    email: Optional[EmailStr] = None
    company_name: Optional[str] = None
    password_hash: Optional[str] = None
    created_at: Optional[datetime] = None

# Schema used for reading/returning a host (e.g., in responses)
class HostReadSchema(BaseModel):
    id: UUID
    host_number: int
    password_hash: str
    created_at: datetime 
    company_name: str
    email: EmailStr # ISO format date string 