
import uuid
from config.logging_config import get_logger
from fastapi.security import HTTPAuthorizationCredentials
from schema import (
    CurrentUserResponseSchema,
    LoginRequestSchema,
    LoginResponseSchema,
    RefreshResponseSchema,
    RefreshDeviceResponseSchema
)
from services import AuthService
from fastapi import HTTPException, Request, Response
from services import AuthService, GuestDeviceService


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


async def logout_handler(
        response: Response, 
        service:AuthService, 
        refresh_token: str | None
    ):
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

async def refresh_device_token_handler(
        device_id: str | None,
        response: Response
    ) -> RefreshDeviceResponseSchema:
    if not device_id:
        uuid = str(uuid.uuid4())
        logger.warning(f"No device ID provided, generated new UUID: {uuid}")
        device_id = uuid

    # Update last seen timestamp, or create if a new device
    await GuestDeviceService.touch_guest_device(device_id) # type: ignore

    # Set device ID in cookie (persistent httponly)
    response.set_cookie(
        key="device_id",
        value=device_id,
        httponly=True,
        secure=IS_PROD,
        samesite="lax",
        max_age=30*24*3600,
        path="/api/auth/device/refresh"
    )

    logger.debug("Device token refreshed successfully")
    return RefreshDeviceResponseSchema(message="Device token refreshed successfully")

