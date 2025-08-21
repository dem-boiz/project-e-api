import traceback
import uuid
import secrets

from config.logging_config import get_logger
from fastapi.security import HTTPAuthorizationCredentials
from schema import CurrentUserResponseSchema, LoginRequestSchema, LoginResponseSchema, RefreshResponseSchema
from services import AuthService
from fastapi import HTTPException, Request, Response, status 
from config import ENV
from utils.utils import verify_jwt, generate_csrf_token
from repository import RefreshTokenRepository

logger = get_logger("auth")

IS_PROD = ENV == "PROD"

async def refresh_token_handler(
    refresh_token: str | None,
    service: AuthService,
    response: Response, 
    request: Request
) -> RefreshResponseSchema:
    return await service.refresh_access_token_service(refresh_token=refresh_token, response=response, request=request)


async def get_me_handler(credentials: HTTPAuthorizationCredentials, service: AuthService) -> CurrentUserResponseSchema:
    """Get current authenticated user"""
    return await service.get_me_service(credentials=credentials)

async def login_handler(
    login_data: LoginRequestSchema,
    response: Response,
    service: AuthService
) -> LoginResponseSchema:  
    return await service.login_service(login_data=login_data, response=response)


async def logout_handler(response: Response, 
                        service:AuthService, 
                        refresh_token: str | None):
    return await service.logout_user_service(response=response, refresh_token=refresh_token)
    
async def global_logout_handler(service: AuthService, 
                               refresh_token: str | None):
    return await service.global_logout_service(refresh_token=refresh_token)

async def kill_session_handler(service: AuthService, sid: uuid.UUID):
    """Kill a session by revoking all refresh tokens associated with the session ID."""
   
    revoked_count = await service.kill_session_service(sid)
    
    if revoked_count > 0:
        return {
            "message": f"Session killed successfully. Revoked {revoked_count} token(s).",
            "revoked_count": revoked_count
        }
    else:
        raise HTTPException(
            status_code=404,
            detail="No active tokens found for the given session ID"
        )
