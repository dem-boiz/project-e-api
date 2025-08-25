import traceback
from jose import jwt, JWTError 
from jose.exceptions import ExpiredSignatureError, JWTClaimsError
from fastapi import Header, Cookie, HTTPException, status, Depends
from config import SECRET_KEY, ALGORITHM, JWT_ACCESS_LIFESPAN, JWT_REFRESH_LIFESPAN
import os, base64, hmac, hashlib
from repository import RefreshTokenRepository
from schema import RefreshTokenCreateSchema
from datetime import datetime, timedelta, timezone
import secrets
import uuid
from typing import Optional
import os
from passlib.context import CryptContext
# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
from config.logging_config import get_logger

PEPPER = os.environ["EVENT_TOKEN_PEPPER"].encode("utf-8")

logger = get_logger("auth")

def hash_crsf(token: str) -> str:
    """Hash a token using HMAC and SHA-256"""
    logger.debug("Hashing token")
    mac = hmac.new(PEPPER, token.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii")

def verify_csrf_hash(plain_token: str, hashed_token: str) -> bool:
    """Verify a token against its hash"""
    logger.debug("Verifying token")
    hashed_new_token = hmac.new(PEPPER, plain_token.encode("utf-8"), hashlib.sha256).digest()
    return hashed_new_token == base64.urlsafe_b64decode(hashed_token)

ISSUER = os.getenv("ISSUER", "SERVER")
AUDIENCE = os.getenv('AUDIENCE', "CLIENT")


# Is this needed?
def generate_otp():
    import random
    return str(random.randint(100000, 999999))

def create_jwt(
    user_id: str,
    jti: uuid.UUID,
    now: datetime,
    lifespan: timedelta,
    session_id: str, 
    remember_me,
    issuer=ISSUER, 
    audience=AUDIENCE
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
    user_id: str,
    session_id: str, 
    remember_me,
    issuer=ISSUER, 
    audience=AUDIENCE
):
    lifespan = timedelta(hours=JWT_ACCESS_LIFESPAN)
    now = datetime.now(timezone.utc)
    jti = uuid.uuid4()

    return create_jwt(
        user_id=user_id,
        now=now,
        lifespan=lifespan,
        session_id=session_id,
        jti=jti,
        remember_me=remember_me,
        issuer=issuer,
        audience=audience
    )

async def create_refresh_token(
    user_id: str,
    session_id: str, 
    remember_me: bool,
    refresh_token_repo: Optional['RefreshTokenRepository'] = None,
    csrf: str | None = None,
    replaced_by_jti: uuid.UUID | None = None,
    parent_jti: uuid.UUID | None = None,
    issuer=ISSUER, 
    audience=AUDIENCE
):
    lifespan = timedelta(days=30) if remember_me else timedelta(hours=JWT_REFRESH_LIFESPAN)
    now = datetime.now(timezone.utc)



    if refresh_token_repo is None:
        raise ValueError("RefreshTokenRepository not provided for storing refresh token")
        
    if csrf is None:
        raise ValueError("CSRF token is required for refresh token")

    csrf_hash = hash_crsf(csrf)
    jti = uuid.uuid4()
    encoded_token = create_jwt(
        user_id=user_id,
        jti=jti,
        now=now,
        lifespan=lifespan,
        session_id=session_id,
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
        raise HTTPException(status_code=500, detail="Internal server error")

    return encoded_token

def verify_jwt(token: str | None, expected_issuer=ISSUER, expected_audience=AUDIENCE, token_type=None):
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
            raise HTTPException(status_code=401, detail=f"Token missing required claims: {missing_claims}")
        
        # Validate token type if specified
        if token_type and payload.get("typ") != token_type:
            logger.warning(f"Token type mismatch. Expected: {token_type}, Got: {payload.get('typ')}")
            raise HTTPException(status_code=401, detail=f"Invalid token type. Expected {token_type}")
        
        # Validate subject (user ID) is present and non-empty
        if not payload.get("sub"):
            logger.warning("JWT has empty or missing subject (user ID)")
            raise HTTPException(status_code=401, detail="Token has invalid subject")
            
        # Validate session ID is present and non-empty
        if not payload.get("sid"):
            logger.warning("JWT has empty or missing session ID")
            raise HTTPException(status_code=401, detail="Token has invalid session ID")
            
        # Validate token ID is present and non-empty
        if not payload.get("jti"):
            logger.warning("JWT has empty or missing token ID")
            raise HTTPException(status_code=401, detail="Token has invalid token ID")
        
        logger.info(f"JWT verified successfully for user {payload['sub']}, session {payload['sid']}")
        return payload
    
    except ExpiredSignatureError as e:
        logger.warning(f"JWT token has expired: {e}")
        raise HTTPException(status_code=401, detail="Token has expired")
    
    except JWTClaimsError as e:
        logger.warning(f"JWT claims validation failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token claims")
    
    except JWTError as e:
        logger.warning(f"Invalid JWT token: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

    except Exception as e:
        logger.error(f"Unexpected error during JWT verification: {e}")
        logger.error(f"Full stack trace:\\n{traceback.format_exc()}")
        raise HTTPException(status_code=401, detail="Token verification failed")
    
def verify_csrf_token(
    x_csrf_token: str = Header(None, alias="X-CSRF-Token"),
    csrf_token: str = Cookie(None, alias="csrf_token")
):
    """Dependency to verify CSRF tokens"""

    print("CSRF Header:", x_csrf_token)
    print("CSRF Cookie:", csrf_token)
    if not x_csrf_token or not csrf_token:
        raise HTTPException(
            status_code=403,
            detail="CSRF token missing"
        )
    
    if x_csrf_token != csrf_token:
        raise HTTPException(
            status_code=403,
            detail="CSRF token mismatch"
        )
    
    return True

async def generate_csrf_token(length: int = 32) -> str:
    """
    Generate a secure random CSRF token.

    Args:
        length (int): Number of bytes before encoding. Defaults to 32 bytes.

    Returns:
        str: URL-safe base64 encoded token.
    """
    return secrets.token_urlsafe(length)



