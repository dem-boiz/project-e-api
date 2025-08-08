import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status
from passlib.context import CryptContext
from models import Host
from schema import LoginRequest, HostCreateSchema
from utils.utils import create_jwt, verify_jwt
from services.host_service import HostService

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.host_service = HostService(db)

    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        return pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)


    async def authenticate_host(self, email: str, password: str) -> Optional[Host]:
        """Authenticate a host by email and password"""
        host = await self.host_service.get_host_by_email(email, True)
        if not host:
            return None
        
        if not self.verify_password(password, host.password_hash):
            return None
            
        return host

    async def login(self, login_data: LoginRequest) -> dict:
        """Login a host and return JWT token"""
        host = await self.authenticate_host(login_data.email, login_data.password)
        if not host:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Create JWT token
        access_token = create_jwt(str(host.id))
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "email": host.email
        }

    async def get_current_host(self, token: str) -> Host:
        """Get current host from JWT token"""
        try:
            userId_str = verify_jwt(token)
            # Convert string UUID back to UUID object
            host_id = uuid.UUID(userId_str)
            host = await self.host_service.get_host_by_id(host_id, False)
            if not host:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Host not found"
                )
            return host
        except ValueError:
            # Handle invalid UUID format
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
