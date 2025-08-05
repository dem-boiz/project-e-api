import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_create_and_hard_delete_otp():
    payload = {
        "email": "testotp@example.com",
        "event_id": "00000000-0000-0000-0000-000000000001"
    }

    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create OTP
        response = await client.post("/otps/create", json=payload)

        assert response.status_code == 201
        data = response.json()
        print("Create OTP Response:", data)
        assert data["email"] == payload["email"]
        assert "otp_code" in data

        # Hard delete OTP
        delete_url = "/otps/delete"
        delete_response = await client.delete(delete_url, params={"otp_code": data["otp_code"]})
        print("Delete OTP URL:", delete_url)
        assert delete_response.status_code == 204
@pytest.mark.asyncio
async def test_create_and_verify_otp():
    payload = {
        "email": "testverify@example.com",
        "event_id": "00000000-0000-0000-0000-000000000001"
    }

    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Step 1: Create OTP
        create_response = await client.post("/otps/create", json=payload)
        assert create_response.status_code == 201

        otp_data = create_response.json()
        print("Create OTP Response:", otp_data)

        # Step 2: Verify OTP
        verify_payload = {
            "email": otp_data["email"],
            "event_id": otp_data["event_id"],
            "otp_code": otp_data["otp_code"]
        }

        verify_response = await client.post("/otps/verify", json=verify_payload)

        print("Verify OTP raw response:", verify_response.text)
        assert verify_response.status_code == 200

        # Now it's safe to parse JSON
        verify_data = verify_response.json()
        print("Verify OTP Response JSON:", verify_data)

        assert verify_data["success"] is True
        assert "verified" in verify_data["message"].lower()