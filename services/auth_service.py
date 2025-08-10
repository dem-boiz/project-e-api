import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status
from passlib.context import CryptContext
from models import Host
from schema import LoginRequest
from utils.utils import create_jwt, verify_jwt
from repository import HostRepository
from config.logging_config import get_logger
import logging

# Silences annoying warning
logging.getLogger("passlib").setLevel(logging.ERROR)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
logger = get_logger("auth")

# TODO: Check authentication token to ensure it's not expired.
# For added security, check issuer, and audience (iss, aud).
class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.host_repo = HostRepository(db)

    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        logger.debug("Hashing password")
        return pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        logger.debug("Verifying password")
        return pwd_context.verify(plain_password, hashed_password)


    async def authenticate_host(self, email: str, password: str) -> Optional[Host]:
        """Authenticate a host by email and password"""
        logger.debug(f"Authentication attempt for email: {email}")
        host = await self.host_repo.get_host_by_email(email)
        if not host:
            logger.warning(f"Host not found for email: {email}")
            return None
        
        if not self.verify_password(password, host.password_hash):
            logger.warning(f"Invalid password for email: {email}")
            return None
        
        logger.debug(f"Host authenticated successfully: {email}")
        # Return a sanitized copy without password hash
        sanitized_host = Host(
            id=host.id,
            host_number=host.host_number,
            email=host.email,
            company_name=host.company_name,
            created_at=host.created_at,
            password_hash=None
        )
        return sanitized_host

    async def login(self, login_data: LoginRequest) -> dict:
        """Login a host and return JWT token"""
        logger.debug(f"Login attempt for email: {login_data.email}")
        host = await self.authenticate_host(login_data.email, login_data.password)
        if not host:
            logger.error(f"Login failed for email: {login_data.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Create JWT token
        access_token = create_jwt(str(host.id))
        logger.debug(f"JWT token created for host: {host.email}")

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "email": host.email,
            "user_id": str(host.id),
            "name": host.company_name,
            "id": str(host.id)
        }

    async def get_current_host(self, token: str) -> Host:
        """Get current host from JWT token"""
        logger.debug(f"Verifying JWT token")
        try:
            userId_str = verify_jwt(token)
            # Convert string UUID back to UUID object
            host_id = uuid.UUID(userId_str)
            logger.debug(f"Token verified for host ID: {host_id}")
            host = await self.host_repo.get_host_by_id(host_id)
            if not host:
                logger.warning(f"Host not found: {host_id}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Host not found"
                )
            # Return a sanitized copy without password hash
            sanitized_host = Host(
                id=host.id,
                host_number=host.host_number,
                email=host.email,
                company_name=host.company_name,
                created_at=host.created_at,
                password_hash=None
            )
            logger.debug(f"Host authenticated successfully: {sanitized_host.email}")
            return sanitized_host
        except ValueError:
            # Handle invalid UUID format
            logger.error(f"Invalid token format: {token}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except Exception as e:
            logger.error(f"Error occurred while verifying token: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Error occurred while verifying token. {e}",
                headers={"WWW-Authenticate": "Bearer"},
            )
