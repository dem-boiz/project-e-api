


from fastapi.security import HTTPAuthorizationCredentials
from schema.auth_schemas import CurrentUserResponse, LoginRequest, LoginResponse, RefreshResponse
from services.auth_service import AuthService


async def handle_refresh_token(credentials: HTTPAuthorizationCredentials, service: AuthService) -> RefreshResponse:
    """Refresh JWT token"""
    token = credentials.credentials
    # Extract host info from the current token (this is the secure approach!)
    host = await service.get_current_host(token)
    # Generate new access token for this host
    return await service.refresh_access_token(str(host.id))


async def handle_get_me(credentials: HTTPAuthorizationCredentials, service: AuthService) -> CurrentUserResponse:
    """Get current authenticated user"""
    token = credentials.credentials
    host = await service.get_current_host(token)
    return CurrentUserResponse(
        email=host.email,
        host_id=str(host.id)
    )

async def handle_login(login_data: LoginRequest, service: AuthService) -> LoginResponse:
    """Handle login for hosts"""
    return await service.login(login_data)