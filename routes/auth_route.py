from config.logging_config import get_logger
from fastapi import APIRouter, Depends, status, Security, Response, Cookie
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from database.session import get_async_session
from models import host
from services import AuthService, HostService
from schema import LoginRequest, LoginResponse, CurrentUserResponse, RefreshResponse

from handlers.auth_handler import handle_refresh_token, handle_get_me, handle_login

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
    result = await handle_login(service, login_data, response)
    logger.info(f"Login successful for email: {login_data.email}")
    return result

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


@router.post("/refresh", response_model=RefreshResponse, status_code=status.HTTP_200_OK)
async def refresh_token(
    refresh_token: str | None = Cookie(default=None),
    service: AuthService = Depends(get_auth_service)
) -> RefreshResponse:
    """Refresh JWT token"""
    logger.debug(f"Refreshing JWT token for host ID: {host.id}")
    result = await handle_refresh_token(refresh_token, service)
    logger.debug(f"New access token generated for host ID: {host.id}")
    return result
