import pytest
from httpx import AsyncClient
from uuid import uuid4
from datetime import datetime, timedelta
from database import AsyncSessionLocal
from models import User, Event, OTP, UserEventAccess
from schema import UserEventAccessCreateSchema

@pytest.mark.asyncio
async def test_create_user_event_access_api():
    async with AsyncSessionLocal() as session:
        # Setup test User, Event, and OTP
        user = User(email=f"testuser_{uuid4()}@example.com")
        event = Event(
            id=uuid4(),
            name="Awesome Event",
            host_id="00000000-0000-0000-0000-000000000001",
            date_time=datetime.now() + timedelta(days=1),
            location="Test Venue",
            description="This is a test description for the event.",
        )
        otp = OTP(
            id=uuid4(),
            email=user.email,
            event_id=event.id,
            otp_code="123456",
            expires_at=datetime.utcnow(),
        )
        session.add_all([user, event, otp])
        await session.commit()

        # Prepare payload for API call
        payload = {
            "user_id": str(user.id),
            "event_id": str(event.id),
            "otp_id": str(otp.id),
        }

    # Use AsyncClient outside of DB session to make the HTTP request
    async with AsyncClient(base_url="http://localhost:8000") as client:
        response = await client.post("/user-event-access/", json=payload)

        assert response.status_code == 201
        data = response.json()
        print(data)

        assert data["user_id"] == payload["user_id"]
        assert data["event_id"] == payload["event_id"]
        assert data["otp_id"] == payload["otp_id"]
        assert "granted_at" in data
        assert data["is_deleted"] is False

    # Optionally verify in DB that record exists
    async with AsyncSessionLocal() as session:
        access = await session.get(UserEventAccess, {"user_id": user.id, "event_id": event.id})
        assert access is not None
        assert access.user_id == user.id
        assert access.event_id == event.id
        assert access.otp_id == otp.id
        assert access.is_deleted is False
