import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient
from services import OTPService
from database import AsyncSessionLocal
from models import OTP
import uuid
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)

def test_generate_otp():
    payload = {
        "email": "otpuser@example.com"
    }
    response = client.post("/otp/generate", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert "otp" in data
    assert data["email"] == payload["email"]

def test_verify_otp():
    async def inner():
        test_email = f"otp_{uuid.uuid4()}@example.com"
        otp_code = "123456"  # Replace with logic to generate or fetch OTP

        async with AsyncSessionLocal() as session:
            # Simulate OTP creation
            new_otp = OTP(email=test_email, otp=otp_code)
            session.add(new_otp)
            await session.commit()
            await session.refresh(new_otp)

            # Verify OTP
            service = OTPService(session)
            is_valid = await service.verify_otp(test_email, otp_code)

            assert is_valid is True

    asyncio.run(inner())

@pytest.mark.asyncio
async def test_generate_duplicate_otp():
    user_data = {"email": "duplicateotp@example.com"}

    async with AsyncClient(app=app, base_url="http://test") as ac:
        # First generation should succeed
        response1 = await ac.post("/otp/generate", json=user_data)
        assert response1.status_code == 201

        # Second generation should fail or return the same OTP, depending on your logic
        response2 = await ac.post("/otp/generate", json=user_data)
        assert response2.status_code in [200, 400, 409]  # Adjust as needed