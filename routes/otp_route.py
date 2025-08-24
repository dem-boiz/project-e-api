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
from handlers import create_otp_handler, delete_otp_handler, verify_otp_handler
router = APIRouter(prefix="/otps", tags=["otps"])

 # Dependency to get OTPService
async def get_otp_service(session: AsyncSession = Depends(get_async_session)) -> OTPService:
    return OTPService(session)

# ✅ Route using handler
@router.post("/create", response_model=OTPResponse, status_code=status.HTTP_201_CREATED)
async def create_otp(
    otp_request: OTPCreateRequest,
    service: OTPService = Depends(get_otp_service),  # ✅ NO parentheses
):
    return await create_otp_handler(otp_request, service)

# Delete OTP by code
@router.delete("/delete", status_code=status.HTTP_204_NO_CONTENT)
async def delete_otp_by_code(
    otp_code: str,
    service: OTPService = Depends(get_otp_service),
):
    return await delete_otp_handler(otp_code, service)