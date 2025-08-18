from config.logging_config import get_logger
from fastapi.security import HTTPAuthorizationCredentials
from schema import CurrentUserResponse, LoginRequest, LoginResponse, RefreshResponse
from services import AuthService
from fastapi import HTTPException, Response, status


from config import ENV
from utils.utils import verify_jwt, generate_csrf_token
import secrets
from repository import RefreshTokenRepository

logger = get_logger("auth")

IS_PROD = ENV == "PROD"

async def handle_refresh_token(
    refresh_token: str | None,
    service: AuthService,
    response: Response
) -> RefreshResponse:
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
    

    # Generate new access + refresh tokens
    tokens = await service.refresh_access_token(
        user_id=user_id,  
        session_id=session_id,
        remember_me=remember_me,
        issuer=issuer,
        audience=audience 
    )
    new_refresh_token = tokens.refresh_token
    remember_me = decoded_token["rm"]

    # Look up the refresh token in the database  
    refresh_token_repo = RefreshTokenRepository(service.db)
    existing_refresh_token = await refresh_token_repo.get_refresh_token_by_jti(new_refresh_token)

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

    # IF used_at is not null, reject the request and set the sessions.revboked_at to now
    if existing_refresh_token.used_at:
        logger.warning("Refresh token has already been used.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has already been used",
            headers={"WWW-Authenticate": "Bearer"},
        )
     

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
        "access_token": tokens.access_token,
        "token_type": "bearer",
        "csrf_token": new_csrf_token
    }

async def handle_get_me(credentials: HTTPAuthorizationCredentials, service: AuthService) -> CurrentUserResponse:
    """Get current authenticated user"""
    token = credentials.credentials
    host = await service.get_current_host(token)
    return CurrentUserResponse(
        email=host.email,
        host_id=str(host.id),
        name=host.company_name
    )

async def handle_login(
    login_data: LoginRequest,
    response: Response,
    service: AuthService
) -> LoginResponse:
    """Handle login for hosts without setting a CSRF cookie."""
    
    # Authenticate user and get tokens
    loginResponse = await service.login(login_data)
    remember_me = login_data.rememberMe

    logger.debug(f"Setting refresh token cookie for host: {login_data.email}")
    response.set_cookie(
        key="refresh_token",
        value=loginResponse["refresh_token"],
        httponly=True,

        secure=True if ENV == "PROD" else False,
        samesite="none" if ENV == "PROD" else "lax",
        max_age=30*24*3600 if remember_me else None,
        path="/auth/refresh"
    )

    # Generate a CSRF token for the client
    csrf_token = await generate_csrf_token()
    logger.debug(f"Generated CSRF token for host: {login_data.email}")

    # ALSO set CSRF token as a cookie (non-httponly so JS can read it)
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,  # JavaScript needs to read this
        secure=True if ENV == "PROD" else False,
        samesite="none" if ENV == "PROD" else "lax",
        max_age=30*24*3600 if remember_me else None,
    )

    logger.debug(f"CSRF token cookie set for host: {login_data.email}")
    logger.debug(f"Login successful for host: {login_data.email}")
    # Build the Pydantic response including CSRF token in the body
    login_response_model = LoginResponse(
        **loginResponse["response_body"],
        csrf_token=csrf_token
    )

    logger.debug(f"Response body prepared with CSRF token for host: {login_data.email}")
    return login_response_model


async def handle_logout(response: Response):

    """Handle logout by deleting access, refresh, and CSRF cookies"""
    is_prod = ENV == "PROD"
    logger.debug("Logging out user, clearing cookies")

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

    logger.debug("All cookies cleared for logout")
    return {"message": "Logged out successfully"}
