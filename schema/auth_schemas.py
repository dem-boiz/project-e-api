from pydantic import BaseModel, EmailStr
from typing import Optional

class LoginRequestSchema(BaseModel):
    email: EmailStr
    password: str
    rememberMe: bool

class LoginResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"
    email: EmailStr
    user_id: str
    name: str
    id: str
    csrf_token: Optional[str] = None  # CSRF token for CSRF protection

class LoginServiceResponseSchema(BaseModel):
    response_body: LoginResponseSchema
    refresh_token: str

class RefreshResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"
    class Config:
        from_attributes = True

class RefreshDeviceResponseSchema(BaseModel):
    message: str
    class Config:
        from_attributes = True

class RefreshTokensSchema(BaseModel):
    access_token: str
    csrf_token: str
    token_type: str = "bearer"

    class Config:
        from_attributes = True

class CurrentUserResponseSchema(BaseModel):
    email: EmailStr
    name: str
    host_id: Optional[str] = None
    
    class Config:
        from_attributes = True

