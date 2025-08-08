from uuid import UUID
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class HostCreateSchema(BaseModel): 
    company_name: str
    email: EmailStr # ISO format date string
    password: str 

class HostUpdateSchema(BaseModel):
    email: Optional[EmailStr] = None
    company_name: Optional[str] = None
    password: Optional[str] = None

# Schema used for reading/returning a host 
class HostReadSchema(BaseModel):
    id: UUID
    host_number: int
    created_at: datetime 
    company_name: str
    email: EmailStr
    class Config:
        from_attributes = True 

    