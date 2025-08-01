from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import uuid
import random
import string

from database.session import get_async_session
from repository import OTPRepository
from models.otp import OTP

router = APIRouter(prefix="/otps", tags=["otps"])

# Pydantic schemas

class OTPCreateRequest(BaseModel):
    email: EmailStr
    event_id: uuid.UUID

class OTPVerifyRequest(BaseModel):
    otp_code: str

class OTPResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    event_id: uuid.UUID
    otp_code: str
    expires_at: datetime
    used: bool
    created_at: datetime

    class Config:
        from_attributes = True


async def generate_unique_otp_code(repo: OTPRepository, length: int = 6) -> str:
    """Generate a unique OTP code not present in DB."""
    chars = string.digits
    max_attempts = 10
    for _ in range(max_attempts):
        code = ''.join(random.choices(chars, k=length))
        existing = await repo.get_otp_by_code(code)
        if existing is None:
            return code
    raise Exception("Failed to generate unique OTP code after multiple attempts")


@router.post("/", response_model=OTPResponse, status_code=status.HTTP_201_CREATED)
async def create_otp(
    otp_request: OTPCreateRequest,
    repo: OTPRepository = Depends(lambda: OTPRepository(get_async_session())),
):
    # Generate a unique OTP code
    async with get_async_session() as session:
        repo = OTPRepository(session)
        otp_code = await generate_unique_otp_code(repo)

        expires_at = datetime.utcnow() + timedelta(minutes=10)  # expires in 10 minutes

        otp = await repo.create_otp(
            email=otp_request.email,
            event_id=otp_request.event_id,
            otp_code=otp_code,
            expires_at=expires_at,
        )
        return otp


@router.post("/verify", response_model=OTPResponse)
async def verify_otp(
    verify_request: OTPVerifyRequest,
    repo: OTPRepository = Depends(lambda: OTPRepository(get_async_session())),
):
    async with get_async_session() as session:
        repo = OTPRepository(session)
        otp = await repo.get_otp_by_code(verify_request.otp_code)
        if otp is None:
            raise HTTPException(status_code=404, detail="OTP not found")
        if otp.used:
            raise HTTPException(status_code=400, detail="OTP already used")
        if otp.expires_at < datetime.utcnow():
            raise HTTPException(status_code=400, detail="OTP expired")

        # Mark OTP as used
        await repo.mark_otp_used(otp.id)
        return otp


@router.delete("/cleanup", status_code=status.HTTP_204_NO_CONTENT)
async def cleanup_expired_otps(
    repo: OTPRepository = Depends(lambda: OTPRepository(get_async_session())),
):
    async with get_async_session() as session:
        repo = OTPRepository(session)
        count = await repo.delete_expired_otps(datetime.utcnow())
    return {"deleted_expired_otps": count}
