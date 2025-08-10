from pydantic import BaseModel, EmailStr
from typing import Optional

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    rememberMe: bool

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    email: EmailStr
    user_id: str
    name: str
    id: str

class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    class Config:
        from_attributes = True

class CurrentUserResponse(BaseModel):
    email: EmailStr
    host_id: Optional[str] = None
    
    class Config:
        from_attributes = True

