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
    return await service.refresh_access_token(refresh_token=refresh_token, response=response)


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


async def handle_logout(response: Response, 
                        service:AuthService, 
                        refresh_token: str | None):
    return await service.logout_user(response=response, refresh_token=refresh_token)
    
async def handle_global_logout(service: AuthService, 
                               refresh_token: str | None):
    return await service.global_logout_service(refresh_token=refresh_token)
