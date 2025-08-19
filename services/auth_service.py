from datetime import datetime, timezone, timedelta
import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status, Response, Cookie 
from passlib.context import CryptContext
from models import Host, Session
from schema import LoginRequest
from schema import RefreshTokens
from schema import SessionCreateSchema
from utils.utils import create_jwt, verify_jwt, generate_csrf_token
from repository import HostRepository, SessionRepository, RefreshTokenRepository
from config.logging_config import get_logger
import logging
from config import ENV
# Silences annoying warning
logging.getLogger("passlib").setLevel(logging.ERROR)
IS_PROD = ENV == "PROD"
# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
logger = get_logger("auth")

# TODO: Check authentication token to ensure it's not expired.
# For added security, check issuer, and audience (iss, aud).
class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.host_repo = HostRepository(db)
        self.session_repo = SessionRepository(db)
        self.refresh_token_repo = RefreshTokenRepository(db)

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
        
        # Create JWT tokens
        user_id = str(host.id)
        sid = uuid.uuid4() 
        sid_str = str(sid) # New session ID for this login
        

        # Create Session record in DB
        session_record = await self.session_repo.create_session(
            session_data=SessionCreateSchema(
                sid=sid,
                user_id=host.id,
                created_at=datetime.now(),
                last_seen_at=datetime.now()
            )
        )
        logger.debug(f"Session record created with SID: {sid} for host: {host.email}")
        # Create refresh token repo 
        refresh_token_repo = RefreshTokenRepository(self.db)
        access_token = await create_jwt(user_id, session_id=sid_str, remember_me=login_data.rememberMe)
        refresh_token = await create_jwt(user_id, session_id=sid_str, remember_me=login_data.rememberMe, refresh_token_repo=refresh_token_repo, type='refresh')

        logger.debug(f"JWT tokens created for host: {host.email}")
        return {
            "response_body": {
                "access_token": access_token,
                "token_type": "bearer",
                "email": host.email,
                "user_id": str(host.id),
                "name": host.company_name,
                "id": str(host.id)
            },
            "refresh_token": refresh_token,
        }


    async def refresh_access_token(self, 
                                   refresh_token: str | None, 
                                   response: Response
                                   ) -> RefreshTokens:
        """Generate a new access & refresh token for the host"""
        
        # Verify Refresh JWT info
        """Refresh JWT token and rotate CSRF token.""" 
        if not refresh_token:
            logger.warning("Missing refresh token.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
        # Verify the refresh token
        try:
            logger.debug(f"Verifying refresh token: {refresh_token}")
            # Decode and verify the JWT
            decoded_token = verify_jwt(refresh_token)
            logger.debug(f"Decoded refresh token: {decoded_token}")
        except HTTPException as e:
            logger.error(f"Refresh token verification failed: {e.detail}")
            raise e
        
        # Get JTI from the token
        jti = decoded_token.get("jti")
        if not jti:
            logger.warning("Refresh token has no JTI (JWT ID) claim.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Get user ID from the token
        user_id = decoded_token.get("sub")
        if not user_id:
            logger.warning("Refresh token has no user ID (sub) claim.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Validate session ID
        session_id = decoded_token.get("sid")
        if not session_id:
            logger.warning("Refresh token has no session ID (sid) claim.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Validate remember_me flag'
        remember_me = decoded_token.get("rm", False)
        if not isinstance(remember_me, bool):   
            logger.warning("Refresh token has invalid remember_me claim.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Validate issuer and audience
        issuer = decoded_token.get("iss")   
        audience = decoded_token.get("aud")
        if not issuer or not audience:
            logger.warning("Refresh token has missing issuer or audience claims.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Look up the refresh token in the database   
        existing_refresh_token = await self.refresh_token_repo.get_refresh_token_by_jti(jti=jti)

        # If no record found, reject the request 
        if not existing_refresh_token:
            logger.warning("Refresh token not found in database.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # IF revoked_at is not null, reject the request
        if existing_refresh_token.revoked_at:
            logger.warning("Refresh token has been revoked.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # IF used_at is not null, reject the request  
        if existing_refresh_token.used_at:
            logger.warning("Refresh token has already been used.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has already been used",
                headers={"WWW-Authenticate": "Bearer"},
        )
        # TODO: set the sessions.revboked_at to now 

        
        # Generate new access + refresh tokens
        logger.debug(f"Generating new access token (& refresh token) for host ID: {user_id}. remember_me optionset to '{remember_me}'")
        access_token = await create_jwt(user_id, session_id, remember_me=remember_me, refresh_token_repo=self.refresh_token_repo, type='access', issuer=issuer, audience=audience)
        refresh_token = await create_jwt(user_id, session_id, remember_me=remember_me, refresh_token_repo=self.refresh_token_repo, type='refresh', issuer=issuer, audience=audience)
        
        # Decode new refresh_token to get new jti 
        decoded_refresh_token = verify_jwt(refresh_token)
        new_jti = decoded_refresh_token["jti"]
        # If valid, set existing token to used
        logger.info(f"Marking token as used {str(jti)}")
        marked_record = await self.refresh_token_repo.mark_refresh_token_as_used(old_jti=jti, new_jti=new_jti)
        logger.info(f"Marked token success: {str(marked_record)}")
        new_refresh_token = refresh_token
        remember_me = decoded_token["rm"]
        # Set updated refresh token as HTTP-only cookie
        logger.debug(f"Setting cookie for refresh token with ENV '{ENV}'")
        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token,
            httponly=True,
            secure=True if ENV == "PROD" else False,
            samesite="none" if ENV == "PROD" else "lax",
            max_age=30*24*3600 if remember_me else None,
            path="/auth/refresh"
        )

        # Rotate CSRF token
        new_csrf_token = await generate_csrf_token()
        logger.debug("Generated new CSRF token for refreshed session.")
        # Also set new CSRF token as cookie (non-httponly)
        response.set_cookie(
            key="csrf_token",
            value=new_csrf_token,
            httponly=False,  # JS needs to read this
            secure=True if ENV == "PROD" else False,
            samesite="none" if ENV == "PROD" else "lax",
            max_age=30*24*3600 if remember_me else None,
        )
        # Return access token and new CSRF token in response body
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "csrf_token": new_csrf_token
        }
        

    async def logout_user(self, 
                          response: Response,
                          refresh_token: str | None):
        """
        Optional: Revoke server-side session/token.
        If you store refresh tokens or sessions in the DB, delete them here.
        """
        # Example: remove token from a session store
        # await self.session_repo.delete_by_user_id(current_user.id)
        """Handle logout by deleting access, refresh, and CSRF cookies"""
        is_prod = ENV == "PROD"
        logger.info("Logging out user, clearing cookies")

        # Verify the refresh token
        try:
            logger.info(f"Verifying refresh token: {refresh_token}")
            # Decode and verify the JWT
            decoded_token = verify_jwt(refresh_token)
            logger.info(f"Decoded refresh token: {decoded_token}")
        except HTTPException as e:
            logger.error(f"Refresh token verification failed: {e.detail}")
            raise e
        
        # Get JTI from the token
        jti = decoded_token.get("jti")
        if not jti:
            logger.warning("Refresh token has no JTI (JWT ID) claim.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Validate session ID
        session_id = decoded_token.get("sid")
        if not session_id:
            logger.warning("Refresh token has no session ID (sid) claim.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            ) 
        
        # Invalidate session in db
        logger.info(f"Checking for sid: {session_id}")
        sid = uuid.UUID(session_id)
        session_invalidated = await self.session_repo.invalidate_session(session_id=sid)
        if session_invalidated is False: 
            raise "Session not invalidated" 
        
        # Delete refresh token cookie
        response.delete_cookie(
            key="refresh_token",
            path="/auth/refresh",
            httponly=True,
            secure=is_prod,
            samesite="none" if is_prod else "lax"
        )

        # Delete CSRF token cookie
        response.delete_cookie(
            key="csrf_token",
            path="/",
            httponly=False,
            secure=is_prod,
            samesite="none" if is_prod else "lax"
        )

        # Delete all refresh tokens from the database
        deleted_refresh_tokens = await self.refresh_token_repo.delete_all_refresh_tokens_by_sid(sid=sid)

        logger.info("All cookies cleared for logout")
        return {"message": "Logged out successfully"}
        
    async def get_current_host(self, token: str) -> Host:
        """Get current host from JWT token"""
        logger.debug(f"Verifying JWT token")
        try:
            decoded_token = verify_jwt(token)
            userId_str = decoded_token["sub"]
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

