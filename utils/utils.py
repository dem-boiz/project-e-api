import traceback
from jose import jwt, JWTError 
from jose.exceptions import ExpiredSignatureError, JWTClaimsError
from fastapi import Header, Cookie, HTTPException, status, Depends
from config import SECRET_KEY, ALGORITHM, JWT_ACCESS_LIFESPAN, JWT_REFRESH_LIFESPAN
from repository import RefreshTokenRepository
from schema import RefreshTokenCreateSchema
from datetime import datetime, timedelta, timezone
import secrets
import uuid
from typing import Optional
import os
from config.logging_config import get_logger

logger = get_logger("auth")


ISSUER = os.getenv("ISSUER", "SERVER")
AUDIENCE = os.getenv('AUDIENCE', "CLIENT")
def generate_otp():
    import random
    return str(random.randint(100000, 999999))
# TODO:  # What should the issuer and audience be? 
async def create_jwt(userId: str,
                     session_id: str, 
                     remember_me,
                     refresh_token_repo: Optional['RefreshTokenRepository'] = None,
                     type="access", 
                     issuer=ISSUER, 
                     audience=AUDIENCE):
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
    # Determine token lifespan
    if type == "access":
        lifespan = timedelta(hours=JWT_ACCESS_LIFESPAN)
    else:
        lifespan = timedelta(days=30) if remember_me else timedelta(hours=JWT_REFRESH_LIFESPAN)
    
    # Current time for issued-at
    now = datetime.now(timezone.utc)
    
    # Create comprehensive payload with all required claims
    payload = {
        "sub": userId,                           # Subject (user ID)
        "sid": str(session_id),                       # Session ID (for session-wide control)
        "jti": str(uuid.uuid4()),               # Token ID (unique per token issuance)
        "iat": int(now.timestamp()),            # Issued at (epoch seconds)
        "exp": int((now + lifespan).timestamp()), # Expiry (epoch seconds)
        "iss": issuer,                          # Issuer
        "aud": audience,                        # Audience
        "typ": type,                            # Token type ("access" or "refresh")
        "rm": remember_me if type == "refresh" else None  # Remember Me flag for refresh tokens
    }  

    if type == "refresh":
        if refresh_token_repo is None:
            raise ValueError("RefreshTokenRepository not provided for storing refresh token")
        
        csrtf_hash = str(uuid.uuid4()).replace("-", "")

        # Create refresh token database record
        token_data = RefreshTokenCreateSchema(
            jti=payload["jti"],
            user_id=str(userId),
            sid=str(session_id),
            expires_at=now + lifespan,
            issued_at=now,
            csrf_hash=csrtf_hash
        )

        try:
            await refresh_token_repo.create_refresh_token(token_data)
        except Exception as e:
            logger.error(f"Error storing refresh token in database: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")
        
    logger.debug(f"Creating {type} JWT for user {userId}, session {session_id}, remember_me={remember_me}")
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)




def verify_jwt(token: str, expected_issuer=ISSUER, expected_audience=AUDIENCE, token_type=None):
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