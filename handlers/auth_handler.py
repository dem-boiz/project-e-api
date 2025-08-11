


from fastapi.security import HTTPAuthorizationCredentials
from schema.auth_schemas import CurrentUserResponse, LoginRequest, LoginResponse, RefreshResponse
from services.auth_service import AuthService
from fastapi import Response

from config import ENV

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

async def handle_login(login_data: LoginRequest, response: Response, service: AuthService) -> LoginResponse:
    """Handle login for hosts"""

    loginResponse = await service.login(login_data)
    response.set_cookie(
        key="refresh_token",
        value=loginResponse["refresh_token"],
        httponly=True,
        secure=True if ENV == "PROD" else False,  # controls whether the cookie is sent only over HTTPS, for dev we want this as false
        samesite="none" if ENV == "PROD" else "lax",  # PROD will have client and server on different domains so samesite=None is needed
        max_age=30*24*3600 if loginResponse["remember_me"] else None, # if the user wants to be remembered, make the cookie last 30 days
        path="/auth/refresh"  # limit cookie to auth endpoint
    )
    return loginResponse