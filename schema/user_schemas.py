from pydantic import BaseModel, EmailStr
from sqlalchemy import  JSON, DateTime 
from uuid import UUID
from datetime import datetime
from typing import Any, Dict, Optional


class UserCreateSchema(BaseModel):
    email: EmailStr # ISO format date string
    password: str 
    name: str
    
    class Config:
        from_attributes = True

class UserReadSchema(BaseModel):
    id: UUID
    email: EmailStr
    user_number: int 
    created_at: datetime
    updated_at: datetime
    is_deleted: bool
    is_active: bool
    name: str

    class Config:
        from_attributes = True


class UserUpdateSchema(BaseModel):
    email: Optional[EmailStr] = None
    name: Optional[str] = None
    password: Optional[str] = None
    description: Optional[str] = None
    contact_info: Optional[Dict[str, Any]] = None