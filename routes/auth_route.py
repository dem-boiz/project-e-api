import os
from config.logging_config import get_logger
from fastapi import APIRouter, Depends, status, Security, Response, Cookie, Header, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from database.session import get_async_session
from models import host
from services import AuthService, HostService
from schema import LoginRequest, LoginResponse, CurrentUserResponse, RefreshResponse
from utils import verify_csrf_token
from handlers import (
    handle_refresh_token, 
    handle_get_me, handle_login, 
    handle_logout,
    handle_refresh_device_token
)

router = APIRouter(prefix="/auth", tags=["authentication"])
security = HTTPBearer()
logger = get_logger("auth")

# Dependency to get AuthService
async def get_auth_service(session: AsyncSession = Depends(get_async_session)) -> AuthService:
    return AuthService(session)

# Dependency to get HostService for registration
async def get_host_service(session: AsyncSession = Depends(get_async_session)) -> HostService:
    return HostService(session)

@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login(
    login_data: LoginRequest,
    response: Response,
    service: AuthService = Depends(get_auth_service),
):
    """Login endpoint for hosts"""
    logger.info(f"Login attempt for email: {login_data.email}")
    result = await handle_login(login_data, response, service)
    logger.info(f"Login successful for email: {login_data.email}")
    # prevent browsers from caching tokens
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return result
    

@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    response: Response,
    service: AuthService = Depends(get_auth_service),
):
    """Logout endpoint with CSRF protection"""
    logger.info("CSRF token verified. Processing logout request")
    return await handle_logout(response)

@router.get("/me", response_model=CurrentUserResponse, status_code=status.HTTP_200_OK)
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    service: AuthService = Depends(get_auth_service)
):
    """Get current authenticated user"""
    logger.debug(f"Getting current user for token: {credentials.credentials}")
    result = await handle_get_me(credentials, service)
    logger.debug(f"Current user retrieved: {result.email}")
    return result


@router.post("/refresh", 
             response_model=RefreshResponse, 
             status_code=status.HTTP_200_OK, 
             dependencies=[Depends(verify_csrf_token)]) # CSRF protection
async def refresh_token(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
    service: AuthService = Depends(get_auth_service) 
) -> RefreshResponse:
    """Refresh JWT token and rotate CSRF token"""
    logger.debug("Refreshing JWT token for host")
    
    result = await handle_refresh_token(refresh_token, service, response)
    
    logger.debug("New access token and CSRF token generated")
    return result
 

@router.post("/device/refresh",
             status_code=status.HTTP_204_NO_CONTENT
             )
async def refresh_device_token(
    response: Response,
    device_token: str | None = Cookie(default=None),
    service: AuthService = Depends(get_auth_service)
) -> RefreshResponse:
    """Refresh device JWT token and rotate CSRF token"""
    logger.debug("Refreshing device JWT token for host")

    result = await handle_refresh_device_token(device_token, service, response)

    logger.debug("New device access token and CSRF token generated")
    return result
