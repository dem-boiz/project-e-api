import os
import uuid
from config.logging_config import get_logger
from fastapi import APIRouter, Depends, Request, status, Security, Response, Cookie, Header, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from database.session import get_async_session
from models import host
from services import AuthService, HostService
from schema import LoginRequestSchema, LoginResponseSchema, CurrentUserResponseSchema, RefreshResponseSchema
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

@router.post("/login", response_model=LoginResponseSchema, status_code=status.HTTP_200_OK)
async def login(
    login_data: LoginRequestSchema,
    response: Response,
    service: AuthService = Depends(get_auth_service),
):
    """Login endpoint for hosts"""
    logger.info(f"Login attempt for email: {login_data.email}")
    result = await login_handler(login_data, response, service)
    logger.info(f"Login successful for email: {login_data.email}")
    # prevent browsers from caching tokens
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return result
    

@router.post("/logout", 
    status_code=status.HTTP_200_OK,
    dependencies =[Depends(verify_csrf_token)]
)
async def logout(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
    service: AuthService = Depends(get_auth_service)
): 
    logger.info("Processing logout request")
    return await logout_handler(response=response, service=service, refresh_token=refresh_token)

# Global logout endpoint
@router.post("/global-logout", status_code=status.HTTP_200_OK)
async def global_logout( 
    refresh_token: str | None = Cookie(default=None),
    service: AuthService = Depends(get_auth_service)
): 
    logger.info("Processing global logout request")
    return await global_logout_handler(service=service, refresh_token=refresh_token)

# Kill session endpoint
@router.post("/kill-session/{sid}", status_code=status.HTTP_200_OK)
async def kill_session(
    sid: uuid.UUID, 
    auth_service: AuthService = Depends(get_auth_service)
):
    return await kill_session_handler(service=auth_service, sid=sid)
    
@router.get("/me", response_model=CurrentUserResponseSchema, status_code=status.HTTP_200_OK)
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    service: AuthService = Depends(get_auth_service)
):
    """Get current authenticated user"""
    logger.debug(f"Getting current user for token: {credentials.credentials}")
    result = await get_me_handler(credentials, service)
    logger.debug(f"Current user retrieved: {result.email}")
    return result


@router.post("/refresh", 
             response_model=RefreshResponseSchema, 
             status_code=status.HTTP_200_OK, 
             dependencies=[Depends(verify_csrf_token)]) # CSRF protection
async def refresh_token(
    response: Response,
    request: Request,
    refresh_token: str | None = Cookie(default=None),
    service: AuthService = Depends(get_auth_service) 
) -> RefreshResponseSchema:
    """Refresh JWT token and rotate CSRF token"""
    logger.debug("Refreshing JWT token for host")
    logger.debug(f"Received refresh token: {refresh_token}")
    result = await refresh_token_handler(refresh_token, service, response, request)
    
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
