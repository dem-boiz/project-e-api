from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import uuid
import random
import string

from database.session import get_async_session 
from services import OTPService
from models.otp import OTP
from schema import OTPCreateRequest, OTPResponse, OTPVerifyRequest, OTPVerifyResponse, OTPDeleteRequest  

router = APIRouter(prefix="/otps", tags=["otps"])
 
# Dependency to get OTPService
async def get_otp_service(session: AsyncSession = Depends(get_async_session)):
    return OTPService(session)

 
# Create OTP Record 
@router.post("/create", response_model=OTPResponse, status_code=status.HTTP_201_CREATED)
async def create_otp(
    otp_request: OTPCreateRequest,
    service: OTPService = Depends(get_otp_service),
):
    otp = await service.generate_otp(otp_request)
    return otp

# Delete OTP by code
@router.delete("/delete", status_code=status.HTTP_204_NO_CONTENT)
async def delete_otp_by_code(
    otp_code: str,
    service: OTPService = Depends(get_otp_service),
):
    deleted = await service.delete_otp(otp_code)
    if not deleted:
        raise HTTPException(status_code=404, detail="OTP not found")
    return {"message": "OTP deleted successfully"}

# Verify OTP by code  
@router.post("/verify", response_model=OTPVerifyResponse)
async def verify_code(
    otp_code: str = Body(..., embed=True),
    email: EmailStr = Body(..., embed=True),
    event_id: str = Body(..., embed=True),
    service: OTPService = Depends(get_otp_service),
):
    verified = await service.verify_otp(email=email, event_id=event_id, otp_code=otp_code)
    if not verified:
        raise HTTPException(status_code=400, detail="OTP could not be verified")

    return OTPVerifyResponse(success=True, message="OTP verified successfully")