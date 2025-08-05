import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient, ASGITransport
from repository import OTPRepository
from services import OTPService
from schema import OTPCreateRequest, OTPResponse, OTPVerifyRequest
from database import AsyncSessionLocal
from models import OTP 
from uuid import UUID, uuid4
import sys
import asyncio
from datetime import datetime

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)
@pytest.mark.asyncio
async def test_create_and_remove_otp():
    async with AsyncSessionLocal() as session: 
        service = OTPService(session) 

        # Create OTP using the service
        otp_request = OTPCreateRequest(
            email="test_email@example.com",
            event_id=UUID("00000000-0000-0000-0000-000000000001")  # or dynamically insert a valid one
        )

        otp = await service.generate_otp(otp_request) 
        assert otp is not None
        assert isinstance(otp, OTP)
        assert otp.email == otp_request.email
        assert otp.event_id == otp_request.event_id
        assert isinstance(otp.expires_at, datetime)
        assert len(otp.otp_code) == 6
        assert otp.used is False 

        # Now delete the OTP using the service 
        delete_request = await service.delete_otp(otp_code=otp.otp_code)
        assert delete_request is True

@pytest.mark.asyncio
async def test_verify_otp():
    async with AsyncSessionLocal() as session: 
        service = OTPService(session) 

        # Create OTP using the service
        otp_request = OTPCreateRequest(
            email="test_email@example.com",
            event_id=UUID("00000000-0000-0000-0000-000000000001")  # or dynamically insert a valid one
        )

        otp = await service.generate_otp(otp_request) 
        assert otp is not None
        assert isinstance(otp, OTP)
        assert otp.email == otp_request.email
        assert otp.event_id == otp_request.event_id
        assert isinstance(otp.expires_at, datetime)
        assert len(otp.otp_code) == 6
        assert otp.used is False 

        # Verify OTP using the service
        verify_request = OTPVerifyRequest(
            email=otp.email,
            event_id=otp.event_id,
            otp_code=otp.otp_code
        )   
        verification_result = await service.verify_otp(
            email=verify_request.email,
            event_id=verify_request.event_id,
            otp_code=verify_request.otp_code
        )
        assert verification_result is True
        # Check if OTP is marked as used
        otp_after_verification = await service.repo.get_otp_by_code(otp.otp_code)
        assert otp_after_verification is not None       
        assert otp_after_verification.used is True
        
        # Now delete the OTP using the service 
        delete_request = await service.delete_otp(otp_code=otp.otp_code)
        assert delete_request is True