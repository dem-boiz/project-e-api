from datetime import datetime, timezone, timedelta
import traceback
import uuid
from typing import Optional
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import false
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, Request, status, Response, Cookie 
from passlib.context import CryptContext
from models import Host, Session
from schema import LoginRequestSchema
from schema import RefreshTokensSchema
from schema import SessionCreateSchema 
from schema.auth_schemas import CurrentUserResponseSchema, LoginResponseSchema
from utils.utils import create_access_token, create_refresh_token, verify_jwt, generate_csrf_token, verify_csrf_hash
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

    async def login_service(self, login_data: LoginRequestSchema, response: Response) -> LoginResponseSchema:

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
        await self.session_repo.create_session(
            session_data=SessionCreateSchema(
                sid=sid,
                user_id=host.id,
                created_at=datetime.now(),
                last_seen_at=datetime.now()
            )
        )
        logger.debug(f"Session record created with SID: {sid} for host: {host.email}")
        # Generate a CSRF token for the client
        csrf_token = await generate_csrf_token()
        logger.debug(f"Generated CSRF token for host: {login_data.email}")
        remember_me = login_data.rememberMe
        # ALSO set CSRF token as a cookie (non-httponly so JS can read it)
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            httponly=False,  # JavaScript needs to read this
            secure=IS_PROD,
            samesite="lax",
            max_age=30*24*3600 if remember_me else None,
            domain=None,  # Set domain only in production (once we have api and client on same domain we need to switch this)
            path="/"  # Available on all paths
        )

        logger.debug(f"CSRF token cookie set for host: {login_data.email}")
        # Create refresh token repo 
        refresh_token_repo = RefreshTokenRepository(self.db)
        access_token = await create_access_token(
            user_id, 
            session_id=sid_str, 
            remember_me=login_data.rememberMe
        )
        refresh_token = await create_refresh_token(
            user_id, 
            session_id=sid_str, 
            remember_me=login_data.rememberMe, 
            refresh_token_repo=refresh_token_repo, 
            csrf=csrf_token
        )
        logger.debug(f"JWT tokens created for host: {host.email}")
        LoginResponse = {
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

        

        logger.debug(f"Setting refresh token cookie for host: {login_data.email}")
        response.set_cookie(
            key="refresh_token",
            value=LoginResponse["refresh_token"],
            httponly=True,
            secure=IS_PROD,
            samesite="lax",
            max_age=30*24*3600 if remember_me else None,
            path="/api/auth"
        )

        
        logger.debug(f"Login successful for host: {login_data.email}")
        # Build the Pydantic response including CSRF token in the body
        login_response_model = LoginResponseSchema(
            **LoginResponse["response_body"],
            csrf_token=csrf_token
        )

        logger.debug(f"Response body prepared with CSRF token for host: {login_data.email}")
        return login_response_model



    async def refresh_access_token_service(self, 
                                   refresh_token: str | None, 
                                   response: Response,
                                   request: Request
                                   ) -> RefreshTokensSchema:
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

        # Get user ID from the token
        user_id = decoded_token.get("sub") 

        # Validate session ID
        session_id = decoded_token.get("sid") 

        # Validate remember_me flag'
        remember_me = decoded_token.get("rm", False)


        # Look up the refresh token in the database   
        existing_refresh_token = await self.refresh_token_repo.get_refresh_token_by_jti(jti=jti)

        if existing_refresh_token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check if token has been revoked
        if existing_refresh_token.revoked_at is not None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check if token has already been used (reuse detection)
        if existing_refresh_token.used_at is not None:
            logger.warning(f"Refresh token reuse detected for JTI: {jti}")
            
            # Revoke the session immediately due to potential token theft
            try:
                await self.session_repo.revoke_all_active_sessions_by_user_id(
                    uuid.UUID(decoded_token["sub"])
                )
                logger.info(f"Session revoked due to token reuse for user: {decoded_token['sub']}")
            except Exception as e:
                logger.error(f"Failed to revoke session after token reuse: {e}")
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token reuse detected",
                headers={"WWW-Authenticate": "Bearer"},
            )

         # Check if token has expired 
        if existing_refresh_token.expires_at and existing_refresh_token.expires_at <= datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired",
                headers={"WWW-Authenticate": "Bearer"},
    ) 
        # Verify the csrf hash
        existing_csrf_hash = existing_refresh_token.csrf_hash 
        logger.info(f"CSRF Hash: {existing_refresh_token.csrf_hash}")
        csrf_token = request.cookies.get("csrf_token")
        logger.info(f"Original CSRF_Token: {csrf_token}")

        if not csrf_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="CSRF token missing",
                headers={"WWW-Authenticate": "Bearer"},
            )

        valid_csrf = verify_csrf_hash(csrf_token, existing_csrf_hash)
        logger.info(f"Valid CSRF: {valid_csrf}")

        if not valid_csrf:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid CSRF token",
                headers={"WWW-Authenticate": "Bearer"},
            )
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

        # Validate that the session is active
        parent_session = await self.session_repo.get_session_by_sid(sid=uuid.UUID(session_id))
        logger.info(f"parent session: {parent_session.revoked_at}")
        if not parent_session or parent_session.revoked_at is not None and parent_session.revoked_at >= decoded_token.get("iat"):
            logger.warning("The parent session for this refresh token is no longer active. Rejecting request")
            raise HTTPException(
                status_code=403,
                detail="Session ended",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Rotate CSRF token
        new_csrf_token = await generate_csrf_token()
        user_id_str = str(user_id)
        session_id_str = str(session_id)
        # Generate new access + refresh tokens
        logger.debug(f"Generating new access token (& refresh token) for host ID: {user_id}. remember_me optionset to '{remember_me}'")
        access_token = await create_access_token(
            user_id=user_id_str, 
            session_id=session_id_str, 
            remember_me=remember_me, 
        )
        refresh_token = await create_refresh_token(
            user_id=user_id_str, 
            session_id=session_id_str, 
            remember_me=remember_me, 
            refresh_token_repo=self.refresh_token_repo, 
            csrf=new_csrf_token,
            parent_jti=jti,
            replaced_by_jti=None
        )


        # TODO: Either also update replaced_by_jti in the parent refresh token, or remove that field from the db model. 

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
            secure=IS_PROD,
            samesite="lax",
            max_age=30*24*3600 if remember_me else None,
            path="/api/auth"
        )
                                       
         
        # Also set new CSRF token as cookie (non-httponly)
        response.set_cookie(
            key="csrf_token",
            value=new_csrf_token,
            httponly=False,  # JS needs to read this
            secure=IS_PROD,
            samesite="lax",
            max_age=30*24*3600 if remember_me else None,
            domain=None,
            path="/" 
        )
        logger.debug("Generated new CSRF token for refreshed session.")
        # Return access token and new CSRF token in response body
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "csrf_token": new_csrf_token,
        }
        
    async def kill_session_service(self, sid: uuid.UUID) -> bool:
        
        '''Kill session given the SID'''
         
        logger.info(f"Killing session for {sid}")

        session_invalidated = await self.session_repo.invalidate_session(sid)
        if session_invalidated is None or session_invalidated is False:
            logger.warning("Session not invalidated.") 
            raise HTTPException(
                status_code=404,
                detail="No active tokens found for the given session ID"
            )
        logger.info("Session tokens successfully revoked")
        return True 

    async def logout_user_service(self, 
                          response: Response,
                          refresh_token: str | None):
        """
        Optional: Revoke server-side session/token.
        If you store refresh tokens or sessions in the DB, delete them here.
        """
        # Example: remove token from a session store
        # await self.session_repo.delete_by_user_id(current_user.id)
        """Handle logout by deleting access, refresh, and CSRF cookies"""
        logger.info("Logging out user, clearing cookies")
        # Delete refresh token cookie
        response.delete_cookie(
            key="refresh_token",
            path="/api/auth",
            httponly=True,
            secure=IS_PROD,
            samesite="lax"
        )

        # Delete CSRF token cookie
        response.delete_cookie(
            key="csrf_token",
            httponly=False,
            secure=IS_PROD,
            samesite="lax",
            domain=None,
            path="/"
        )
        # Only try to invalidate server-side tokens if refresh token exists
        if refresh_token is None:
            logger.info("No refresh token provided, only clearing cookies")
            return {"message": "Logged out successfully"}
        
        # Verify the refresh token
        try:
            logger.info(f"Verifying refresh token: {refresh_token}")
            # Decode and verify the JWT
            decoded_token = verify_jwt(refresh_token)
            logger.info(f"Decoded refresh token: {decoded_token}")
        except HTTPException as e:
            logger.error(f"Refresh token verification failed: {e.detail}")
            raise e

        
        # Validate session ID
        session_id = decoded_token.get("sid")
        
        # Invalidate session in db
        logger.info(f"Checking for sid: {session_id}")
        sid = uuid.UUID(session_id)
        session_invalidated = await self.session_repo.invalidate_session(session_id=sid)
        if session_invalidated is False: 
            raise "Session not invalidated"  

        # Delete all refresh tokens from the database
        # deleted_refresh_tokens = await self.refresh_token_repo.delete_all_refresh_tokens_by_sid(sid=sid)

        logger.info("All cookies cleared for logout")
        return {"message": "Logged out successfully"}
    
    async def get_me_service(self, credentials:HTTPAuthorizationCredentials) -> CurrentUserResponseSchema:
        """Get current authenticated user"""
        token = credentials.credentials
        host = await self.get_current_host_service(token)
        return CurrentUserResponseSchema(
            email=host.email,
            host_id=str(host.id),
            name=host.company_name
        )
    async def get_current_host_service(self, token: str) -> Host:
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

    async def validate_session_is_active(self, token: str):
        # this is duplicate work. Look for a way to reduce this
        decoded_token = verify_jwt(token)
        parent_session = await self.session_repo.get_session_by_sid(decoded_token["sid"])
        
        if parent_session is None:
            return False
        if parent_session.revoked_at == None or parent_session.revoked_at <= decoded_token["iat"]:
            return True
        return False

        

    async def global_logout_service(self, 
                                refresh_token: str | None):
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

        # Get user ID from the token
        user_id = decoded_token.get("sub")

        # Revoke in the repository
        sessions_revoked = await self.session_repo.revoke_all_active_sessions_by_user_id(uuid.UUID(user_id))

        # Remove refresh token records from db 
        #tokens_revoked = await self.refresh_token_repo.delete_all_refresh_tokens_by_user_id(uuid.UUID(user_id))

        logger.info(f"Global logout for user {user_id}: sessions_revoked={sessions_revoked}")

        return {"message": "All sessions and tokens revoked successfully"}
