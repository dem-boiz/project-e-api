from fastapi import APIRouter, Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from database.session import get_async_session
from services import AuthService, HostService
from schema import LoginRequest, LoginResponse, CurrentUserResponse, LogoutResponse, HostCreateSchema, HostReadSchema

router = APIRouter(prefix="/auth", tags=["authentication"])
security = HTTPBearer()

# Dependency to get AuthService
async def get_auth_service(session: AsyncSession = Depends(get_async_session)) -> AuthService:
    return AuthService(session)

# Dependency to get HostService for registration
async def get_host_service(session: AsyncSession = Depends(get_async_session)) -> HostService:
    return HostService(session)

@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login(
    login_data: LoginRequest,
    service: AuthService = Depends(get_auth_service)
):
    """Login endpoint for hosts"""
    return await service.login(login_data)

@router.get("/me", response_model=CurrentUserResponse, status_code=status.HTTP_200_OK)
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    service: AuthService = Depends(get_auth_service)
):
    """Get current authenticated user"""
    token = credentials.credentials
    host = await service.get_current_host(token)
    return CurrentUserResponse(
        email=host.email,
        host_id=str(host.id)
    )

@router.post("/logout", response_model=LogoutResponse, status_code=status.HTTP_200_OK)
async def logout(
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    """Logout endpoint (client-side token invalidation)"""
    # JWT tokens are stateless, so logout is handled client-side
    # In a production environment, you might want to maintain a blacklist
    return LogoutResponse(message="Successfully logged out")