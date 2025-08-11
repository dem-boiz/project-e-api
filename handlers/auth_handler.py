


from config.logging_config import get_logger
from fastapi.security import HTTPAuthorizationCredentials
from schema import CurrentUserResponse, LoginRequest, LoginResponse, RefreshResponse
from services.auth_service import AuthService
from fastapi import HTTPException, Response, status


from config import ENV
from utils.utils import verify_jwt

logger = get_logger("auth")


async def handle_refresh_token(refresh_token, service: AuthService, response: Response) -> RefreshResponse:
    """Refresh JWT token"""
    if not refresh_token:
        # Handle missing refresh token
        logger.warning("Missing refresh token.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    logger.debug(f"Refresh token found. Retrieving host info.")
    # Extract host info from the current token (this is the secure approach!)
    decoded_token = verify_jwt(refresh_token)
    logger.debug("Host info found. Refreshing access & refresh tokens.")
    # Generate new access token for this host
    tokens = await service.refresh_access_token(str(decoded_token["sub"]), decoded_token["rm"])

    # refresh token must be stored as HTTP only cookie
    response.set_cookie(
        key="refresh_token",
        value=tokens["refresh_token"],
        httponly=True,
        secure=True if ENV == "PROD" else False,
        samesite="none" if ENV == "PROD" else "lax",
        max_age=30*24*3600 if tokens["remember_me"] else None,
        path="/auth/refresh"
    )

    # access token can be sent back via response body
    return {
        "access_token": tokens["access_token"],
        "token_type": "bearer"
    }


async def handle_get_me(credentials: HTTPAuthorizationCredentials, service: AuthService) -> CurrentUserResponse:
    """Get current authenticated user"""
    token = credentials.credentials
    host = await service.get_current_host(token)
    return CurrentUserResponse(
        email=host.email,
        host_id=str(host.id)
    )

async def handle_login(login_data: LoginRequest, response: Response, service: AuthService) -> LoginResponse:
    """Handle login for hosts"""
    loginResponse = await service.login(login_data)
    remember_me = login_data.rememberMe
    logger.debug(f"Setting refresh token cookie for host: {login_data.email}")
    response.set_cookie(
        key="refresh_token",
        value=loginResponse["refresh_token"],
        httponly=True,
        secure=True if ENV == "PROD" else False,  # controls whether the cookie is sent only over HTTPS, for dev we want this as false
        samesite="none" if ENV == "PROD" else "lax",  # PROD will have client and server on different domains so samesite=None is needed
        max_age=30*24*3600 if remember_me else None, # if the user wants to be remembered, make the cookie last 30 days
        path="/auth/refresh"  # limit cookie to auth endpoint
    )
    logger.debug(f"Refresh token cookie successfully set for host: {login_data.email}")

    return loginResponse["response_body"]