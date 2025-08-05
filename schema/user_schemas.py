from pydantic import BaseModel, EmailStr
from uuid import UUID
from datetime import datetime
from typing import Optional


class UserCreate(BaseModel):
    email: EmailStr 
    class Config:
        from_attribute = True

class UserRead(BaseModel):
    id: UUID
    email: EmailStr
    created_at: datetime
    is_deleted: bool
    class Config:
        from_attributes = True