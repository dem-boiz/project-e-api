from fastapi import Depends, status, HTTPException
from services import OTPService
from schema import OTPCreateRequest, OTPResponse , OTPVerifyResponse
from sqlalchemy.ext.asyncio import AsyncSession
from database.session import get_async_session


async def create_otp_handler(otp_request: OTPCreateRequest, service: OTPService) -> OTPResponse:
    return await service.generate_otp(otp_request)

async def delete_otp_handler(otp_request: str, service: OTPService) -> OTPResponse:
    deleted = await service.delete_otp(otp_request)
    if not deleted:
        raise HTTPException(status_code=404, detail="OTP not found")
    return {"message": "OTP deleted successfully"} 

async def verify_otp_handler(
    otp_code: str,            
    email: str,
    event_id: str,
    service: OTPService,
) -> OTPVerifyResponse:
    verified = await service.verify_otp(email=email, event_id=event_id, otp_code=otp_code)
    if not verified:
        raise HTTPException(status_code=400, detail="OTP could not be verified")

    return OTPVerifyResponse(success=True, message="OTP verified successfully")
