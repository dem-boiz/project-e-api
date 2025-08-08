import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status
from passlib.context import CryptContext
from repository import HostRepository
from models import Host
from schema import LoginRequest, HostCreateSchema
from utils.utils import create_jwt, verify_jwt

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.host_repo = HostRepository(db)

    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        return pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)

    async def register_host(self, data: HostCreateSchema) -> Host:
        """Register a new host with hashed password"""
        # Check if host with email already exists
        existing = await self.host_repo.get_host_by_email(data.email)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Host already exists with this email"
            )
        
        # Hash the password before storing
        hashed_password = self.hash_password(data.password)
        
        # Create host with hashed password
        new_host = Host(
            id=uuid.uuid4(),
            email=data.email,
            company_name=data.company_name,
            password_hash=hashed_password
        )
        
        self.db.add(new_host)
        await self.db.commit()
        await self.db.refresh(new_host)
        return new_host

    async def authenticate_host(self, email: str, password: str) -> Optional[Host]:
        """Authenticate a host by email and password"""
        host = await self.host_repo.get_host_by_email(email)
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
            userId = verify_jwt(token)
            host = await self.host_repo.get_host_by_id(userId)
            if not host:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Host not found"
                )
            return host
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
