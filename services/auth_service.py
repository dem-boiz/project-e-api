from datetime import datetime, timedelta, timezone
import secrets
import traceback
import uuid
from typing import Optional
from fastapi import Cookie, Depends, Header, Security
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, Request, status, Response 
from passlib.context import CryptContext
from config.settings import SECRET_KEY
from database.session import get_async_session
from schema import (
    LoginRequestSchema, 
    UserReadSchema, 
    RefreshTokensSchema,
    SessionCreateSchema
)
import base64, hmac, hashlib
from jose import jwt, JWTError 
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

from schema.auth_schemas import CurrentUserResponseSchema, LoginResponseSchema

from repository import SessionRepository, RefreshTokenRepository, UserRepository
from config.logging_config import get_logger
import logging
from config import ENV, ISSUER, AUDIENCE, ALGORITHM, JWT_ACCESS_LIFESPAN, JWT_REFRESH_LIFESPAN, CSRF_PEPPER
from schema.refresh_token_schemas import RefreshTokenCreateSchema
from services.event_service import EventService
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# Silences annoying warning
logging.getLogger("passlib").setLevel(logging.ERROR)
IS_PROD = ENV == "PROD"
# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
logger = get_logger("auth")


class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_repo = UserRepository(db)
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

    async def authenticate_user(self, email: str, password: str) -> Optional[UserReadSchema]:
        """Authenticate a user by email and password"""
        logger.debug(f"Authentication attempt for email: {email}")
        user = await self.user_repo.get_user_by_email(email)


        if not user:
            logger.warning(f"user not found for email: {email}")
            return None
        
        if not user.password_hash:  
            logger.warning(f"No password hash found for user: {email}")
            return None
        
        if not self.verify_password(password, user.password_hash):
            logger.warning(f"Invalid password for email: {email}")
            return None
        
        logger.debug(f"user authenticated successfully: {email}") 
        return user

    async def login_service(self, login_data: LoginRequestSchema, response: Response) -> LoginResponseSchema: 
        """Login a user and return JWT token"""
        logger.debug(f"Login attempt for email: {login_data.email}")
        user = await self.authenticate_user(login_data.email, login_data.password)
        if not user:
            logger.error(f"Login failed for email: {login_data.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Create JWT tokens
        user_id = str(user.id)
        sid = uuid.uuid4() 
        sid_str = str(sid) # New session ID for this login
        

        # Create Session record in DB
        await self.session_repo.create_session(
            session_data=SessionCreateSchema(
                sid=sid,
                user_id=user.id,
                created_at=datetime.now(),
                last_seen_at=datetime.now()
            )
        )
        logger.debug(f"Session record created with SID: {sid} for user: {user.email}")
        # Generate a CSRF token for the client
        csrf_token = await self.generate_csrf_token()
        logger.debug(f"Generated CSRF token for user: {login_data.email}")
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

        logger.debug(f"CSRF token cookie set for user: {login_data.email}")
        # Create refresh token repo 
        refresh_token_repo = RefreshTokenRepository(self.db)
        access_token = await self.create_access_token(
            user_id, 
            session_id=sid_str, 
            remember_me=login_data.rememberMe
        )
        refresh_token = await self.create_refresh_token(
            user_id, 
            session_id=sid_str, 
            remember_me=login_data.rememberMe, 
            refresh_token_repo=refresh_token_repo, 
            csrf=csrf_token
        )
        logger.debug(f"JWT tokens created for user: {user.email}")
        LoginResponse = {
            "response_body": {
                "access_token": access_token,
                "token_type": "bearer",
                "email": user.email,
                "user_id": str(user.id),
                "name": user.name,
                "id": str(user.id)
            },
            "refresh_token": refresh_token,
        }

        

        logger.debug(f"Setting refresh token cookie for user: {login_data.email}")
        response.set_cookie(
            key="refresh_token",
            value=LoginResponse["refresh_token"],
            httponly=True,
            secure=IS_PROD,
            samesite="lax",
            max_age=30*24*3600 if remember_me else None,
            path="/api/auth"
        )

        
        logger.debug(f"Login successful for user: {login_data.email}")
        # Build the Pydantic response including CSRF token in the body
        login_response_model = LoginResponseSchema(
            **LoginResponse["response_body"],
            csrf_token=csrf_token
        )

        logger.debug(f"Response body prepared with CSRF token for user: {login_data.email}")
        return login_response_model



    async def refresh_access_token_service(
        self, 
        refresh_token: str | None, 
        response: Response,
        request: Request
    ) -> RefreshTokensSchema:
        """Generate a new access & refresh token for the user"""
        
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
            decoded_token = self.verify_jwt(refresh_token)
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

        # Validate remember_me flag
        remember_me = decoded_token.get("rm", False)


        # Look up the refresh token in the database   
        existing_refresh_token = await self.refresh_token_repo.get_refresh_token_by_jti(jti=str(jti))

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

        valid_csrf = self.verify_csrf_hash(csrf_token, existing_csrf_hash)
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
        iat = decoded_token.get("iat")

        if not parent_session or (
            parent_session.revoked_at is not None 
            and iat is not None 
            and parent_session.revoked_at >= datetime.fromtimestamp(iat, tz=timezone.utc)
        ):
            logger.warning("The parent session for this refresh token is no longer active. Rejecting request")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Session ended",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Rotate CSRF token
        new_csrf_token = await self.generate_csrf_token()
        user_id_str = str(user_id)
        session_id_str = str(session_id)
        # Generate new access + refresh tokens
        logger.debug(f"Generating new access token (& refresh token) for user ID: {user_id}. remember_me optionset to '{remember_me}'")
        access_token = await self.create_access_token(
            user_id=user_id_str, 
            session_id=session_id_str, 
            remember_me=remember_me, 
        )
        refresh_token = await self.create_refresh_token(
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
        decoded_refresh_token = self.verify_jwt(refresh_token)
        new_jti = decoded_refresh_token["jti"]
        # If valid, set existing token to used
        logger.info(f"Marking token as used {str(jti)}")
        marked_record = await self.refresh_token_repo.mark_refresh_token_as_used(old_jti=uuid.UUID(jti), new_jti=new_jti)
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
        return RefreshTokensSchema(
            access_token=access_token,
            csrf_token=new_csrf_token,
        )
        
    async def kill_session_service(self, sid: uuid.UUID) -> bool:
        
        '''Kill session given the SID'''
         
        logger.info(f"Killing session for {sid}")

        session_invalidated = await self.session_repo.invalidate_session(sid)
        if session_invalidated is None or session_invalidated is False:
            logger.warning("Session not invalidated.") 
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
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
            decoded_token = self.verify_jwt(refresh_token)
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
            logger.error(f"Session \"{sid}\" failed to be invalidated")
            raise Exception("Session not invalidated")

        # Delete all refresh tokens from the database
        # deleted_refresh_tokens = await self.refresh_token_repo.delete_all_refresh_tokens_by_sid(sid=sid)

        logger.info("All cookies cleared for logout")
        return {"message": "Logged out successfully"}
    
    async def get_me_service(self, credentials:HTTPAuthorizationCredentials) -> CurrentUserResponseSchema:
        """Get current authenticated user"""
        token = credentials.credentials

        user = await self.get_current_user_service(token)
        if not user:
            logger.warning(f"User not found for token: {token}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return CurrentUserResponseSchema(
            email=user.email,
            user_id=str(user.id),
            name=user.name
        )

    async def get_current_user_service(self, token: str, graceful: bool = False) -> UserReadSchema | None:
        """Get current user from JWT token"""
        logger.debug(f"Verifying JWT token")
        try:
            decoded_token = self.verify_jwt(token)
            userId_str = decoded_token["sub"]
            # Convert string UUID back to UUID object
            user_id = uuid.UUID(userId_str)
            logger.debug(f"Token verified for user ID: {user_id}")
            user = await self.user_repo.get_user_by_id(user_id)
            if not user:
                logger.warning(f"User not found: {user_id}")
                if graceful:
                    return None
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
             
            logger.debug(f"User authenticated successfully: {user.email}")
            return user
        
        except ValueError:
            # Handle invalid UUID format
            logger.error(f"Invalid token format: {token}")
            if graceful:
                return None
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except Exception as e:
            logger.error(f"Error occurred while verifying token: {e}")
            if graceful:
                return None
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Error occurred while verifying token. {e}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    async def validate_session_is_active(self, token: str):
        # this is duplicate work. Look for a way to reduce this
        decoded_token = self.verify_jwt(token)
        parent_session = await self.session_repo.get_session_by_sid(decoded_token["sid"])
        
        if parent_session is None:
            return False
        
        # If session isn't revoked, it's active
        if parent_session.revoked_at is None:
            return True
            
        # Compare timestamps: session revocation time vs token issue time
        revoked_timestamp = int(parent_session.revoked_at.timestamp())
        if revoked_timestamp <= decoded_token["iat"]:
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
            decoded_token = self.verify_jwt(refresh_token)
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

    def create_jwt(
        self,
        user_id: str,
        jti: uuid.UUID,
        now: datetime,
        lifespan: timedelta,
        session_id: str,
        type:str,
        remember_me,
        issuer=ISSUER, 
        audience=AUDIENCE,
    ):
        """
        Create a JWT token with comprehensive claims for security and session management.
        
        Args:
            userId (str): The user ID (subject)
            session_id (str): Session ID for this login session (allows session-wide logout)
            type (str): Token type - "access" or "refresh"
            remember_me (bool): Whether this is a "remember me" login (affects refresh token lifespan)
            issuer (str): Token issuer identifier
            audience (str): Token audience identifier
        
        Returns:
            str: Encoded JWT token
        """

        if SECRET_KEY is None:
            logger.error("SECRET_KEY is not set")
            raise ValueError("Fatal JWT Error: Missing SECRET_KEY.")

        # Create comprehensive payload with all required claims
        payload = {
            "sub": user_id,                           # Subject (user ID)
            "sid": str(session_id),                       # Session ID (for session-wide control)
            "jti": str(jti),                               # Token ID (unique per token issuance)
            "iat": int(now.timestamp()),            # Issued at (epoch seconds)
            "exp": int((now + lifespan).timestamp()), # Expiry (epoch seconds)
            "iss": issuer,                          # Issuer
            "aud": audience,                        # Audience
            "typ": type,                            # Token type ("access" or "refresh")
            "rm": remember_me if remember_me else None  # Remember Me flag for refresh tokens
        }

        logger.debug(f"Creating {type} JWT for user {user_id}, session {session_id}, remember_me={remember_me}")
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    
    async def create_access_token(
        self,
        user_id: str,
        session_id: str, 
        remember_me,
        issuer=ISSUER, 
        audience=AUDIENCE
    ):
        lifespan = timedelta(hours=JWT_ACCESS_LIFESPAN)
        now = datetime.now(timezone.utc)
        jti = uuid.uuid4()

        return self.create_jwt(
            user_id=user_id,
            now=now,
            lifespan=lifespan,
            session_id=session_id,
            type="access",
            jti=jti,
            remember_me=remember_me,
            issuer=issuer,
            audience=audience,
        )

    async def create_refresh_token(
        self,
        user_id: str,
        session_id: str, 
        remember_me: bool,
        refresh_token_repo: Optional['RefreshTokenRepository'] = None,
        csrf: str | None = None,
        replaced_by_jti: uuid.UUID | None = None,
        parent_jti: uuid.UUID | None = None,
        issuer=ISSUER, 
        audience=AUDIENCE
    ) -> str:
        lifespan = timedelta(days=30) if remember_me else timedelta(hours=JWT_REFRESH_LIFESPAN)
        now = datetime.now(timezone.utc)

        if refresh_token_repo is None:
            raise ValueError("RefreshTokenRepository not provided for storing refresh token")
            
        if csrf is None:
            raise ValueError("CSRF token is required for refresh token")

        csrf_hash = self.hash_csrf(csrf)
        jti = uuid.uuid4()
        encoded_token = self.create_jwt(
            user_id=user_id,
            jti=jti,
            now=now,
            lifespan=lifespan,
            session_id=session_id,
            type="refresh",
            remember_me=remember_me,
            issuer=issuer,
            audience=audience
        )

        # Create refresh token database record
        token_data = RefreshTokenCreateSchema(
            jti=jti,
            user_id=user_id,
            sid=session_id,
            expires_at=now + lifespan,
            issued_at=now,
            csrf_hash=csrf_hash,
            replaced_by_jti=replaced_by_jti,
            parent_jti=parent_jti
        )

        try:
            await refresh_token_repo.create_refresh_token(token_data)
        except Exception as e:
            logger.error(f"Error storing refresh token in database: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

        return encoded_token

    def verify_jwt(self, token: str | None, expected_issuer=ISSUER, expected_audience=AUDIENCE, token_type=None):
        """
        Verifies the JWT token by decoding it and validating all claims.
        
        Args:
            token (str): JWT token to verify
            expected_issuer (str): Expected issuer claim value
            expected_audience (str): Expected audience claim value
            token_type (str, optional): Expected token type ("access" or "refresh")
        
        Returns:
            dict: Decoded payload if valid
            
        Raises:
            HTTPException: Various 401 errors for different validation failures
        """

        if not token:
            logger.warning("Missing JWT token.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing JWT token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if SECRET_KEY is None:
            logger.error("SECRET_KEY is not set")
            raise ValueError("Fatal JWT Error: Missing SECRET_KEY.")

        try:
            # Decode with comprehensive validation
            payload = jwt.decode(
                token, 
                SECRET_KEY, 
                algorithms=[ALGORITHM],
                # Validate standard claims
                options={
                    "require": ["sub", "sid", "jti", "iat", "exp", "iss", "aud", "typ"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True
                },
                issuer=expected_issuer,
                audience=expected_audience
            )
            
            # Validate custom claims
            required_claims = ["sub", "sid", "jti", "iat", "exp", "iss", "aud", "typ"]
            missing_claims = [claim for claim in required_claims if claim not in payload]
            if missing_claims:
                logger.warning(f"JWT missing required claims: {missing_claims}")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token missing required claims: {missing_claims}")
            
            # Validate token type if specified
            if token_type and payload.get("typ") != token_type:
                logger.warning(f"Token type mismatch. Expected: {token_type}, Got: {payload.get('typ')}")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token type. Expected {token_type}")
            
            # Validate subject (user ID) is present and non-empty
            if not payload.get("sub"):
                logger.warning("JWT has empty or missing subject (user ID)")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has invalid subject")
                
            # Validate session ID is present and non-empty
            if not payload.get("sid"):
                logger.warning("JWT has empty or missing session ID")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has invalid session ID")
                
            # Validate token ID is present and non-empty
            if not payload.get("jti"):
                logger.warning("JWT has empty or missing token ID")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has invalid token ID")
            
            logger.info(f"JWT verified successfully for user {payload['sub']}, session {payload['sid']}")
            return payload
        
        except ExpiredSignatureError as e:
            logger.warning(f"JWT token has expired: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")

        except JWTClaimsError as e:
            logger.warning(f"JWT claims validation failed: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token claims")

        except JWTError as e:
            logger.warning(f"Invalid JWT token: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        except Exception as e:
            logger.error(f"Unexpected error during JWT verification: {e}")
            logger.error(f"Full stack trace:\\n{traceback.format_exc()}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token verification failed")
        


    async def generate_csrf_token(self, length: int = 32) -> str:
        """
        Generate a secure random CSRF token.

        Args:
            length (int): Number of bytes before encoding. Defaults to 32 bytes.

        Returns:
            str: URL-safe base64 encoded token.
        """
        return secrets.token_urlsafe(length)

    # Dependency to get current authenticated user
    
    def hash_csrf(self, token: str) -> str:
        """Hash a token using HMAC and SHA-256"""
        logger.debug("Hashing token")
        mac = hmac.new(CSRF_PEPPER, token.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode("ascii")

    def verify_csrf_hash(self, plain_token: str, hashed_token: str) -> bool:
        """Verify a token against its hash"""
        logger.debug("Verifying token")
        hashed_new_token = hmac.new(CSRF_PEPPER, plain_token.encode("utf-8"), hashlib.sha256).digest()
        return hashed_new_token == base64.urlsafe_b64decode(hashed_token)




def verify_csrf_token(
    x_csrf_token: str = Header(None, alias="X-CSRF-Token"),
    csrf_token: str = Cookie(None, alias="csrf_token")
):
    """Dependency to verify CSRF tokens"""

    print("CSRF Header:", x_csrf_token)
    print("CSRF Cookie:", csrf_token)
    if not x_csrf_token or not csrf_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing"
        )
    
    if x_csrf_token != csrf_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch"
        )
    
    return True



# Note: HttpBearer automatically checks for the existence of a token but does not validate it. 
security = HTTPBearer()
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    async_session: AsyncSession = Depends(get_async_session)
) -> UserReadSchema | None:
    """Get the current authenticated user from JWT token"""
    token = credentials.credentials
    auth_service: AuthService = AuthService(async_session)
    return await auth_service.get_current_user_service(token, graceful=False)


# Separate dependency for graceful user retrieval without mandatory authentication
async def get_current_user_graceful(
    request: Request,
    async_session: AsyncSession = Depends(get_async_session)
) -> UserReadSchema | None:
    """Get the current user if authenticated, or None if not authenticated"""
    logger.debug("Getting current user with graceful authentication")
    auth_service: AuthService = AuthService(async_session)  
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        logger.debug("No bearer token found, returning None (graceful)")
        return None
        
    token = auth_header.split(" ")[1]
    return await auth_service.get_current_user_service(token, graceful=True)
  
  
async def validate_token_parent_session(
    credentials: HTTPAuthorizationCredentials = Security(security),
    async_session: AsyncSession = Depends(get_async_session)
) -> None:
    """ validate token parent session by checking that it hasnt been revoked"""
    auth_service: AuthService = AuthService(async_session)
    isActive = await auth_service.validate_session_is_active(credentials.credentials)

    if isActive == False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="session expired"
        )
    
    return 

async def get_device_id(
        request: Request
) -> uuid.UUID | None:
    """Get the device ID from the cookie"""
    device_id_str = request.cookies.get("device_id")
    logger.debug(f"Got device ID from cookie: {device_id_str}")
    if device_id_str:
        try:
            return uuid.UUID(device_id_str)
        except ValueError:
            # Invalid UUID format in cookie
            return None
    return None

# Dependency to verify event ownership. unlike the previous one, this one does not require the update data.
# TODO: Replace all usage of above method to use this one instead? 
async def verify_event_ownership(
    event_id: uuid.UUID,
    current_user: UserReadSchema = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session)
) -> tuple[uuid.UUID, UserReadSchema]:
    """Verify that the authenticated user owns the event"""
    try:
        logger.debug(f"Verifying ownership for event: {event_id} and user: {current_user.id}")
        event_service = EventService(session)
        event = await event_service.get_event_by_id(event_id=event_id)

        if event.host_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only update events that you own"
            )
    
        return event_id, current_user
    except ValueError:
        logger.error(f"Invalid event ID format: {event_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid event ID format"
        )
    except Exception as e:
        logger.error(f"Error verifying event ownership: {e}")
        raise HTTPException(
            status_code=getattr(e, 'status_code', status.HTTP_404_NOT_FOUND),
            detail=f"Error occured. {e}"
        )
