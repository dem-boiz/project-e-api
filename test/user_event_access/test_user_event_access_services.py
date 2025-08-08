import pytest
from uuid import uuid4
from datetime import datetime, timedelta

from models import User, Event, OTP, UserEventAccess, Host
from services import UserEventAccessService
from schema import UserEventAccessCreateSchema
from database import AsyncSessionLocal  # assuming you have this already


@pytest.mark.asyncio
async def test_create_user_event_access():
    async with AsyncSessionLocal() as session: 

        # Setup test User, Event, and OTP
        user = User(email=f"testuser_{uuid4()}@example.com")
        event = Event(
            id=uuid4(),
            name="Awesome Event",
            host_id="00000000-0000-0000-0000-000000000001",
            date_time=datetime.now() + timedelta(days=1),  # ✅ pass datetime object
            location="Test Venue",
            description="This is a test description for the event.", 
        ) 
        otp = OTP(id=uuid4(), email=user.email, event_id=event.id, otp_code="123456", expires_at=datetime.utcnow())

        session.add_all([user, event, otp])
        await session.commit()

        # Instantiate service
        service = UserEventAccessService(session)

        # Prepare schema
        schema = UserEventAccessCreateSchema(
            user_id=user.id,
            event_id=event.id,
            otp_id=otp.id
        )

        # Create access
        await service.create_user_event_access(schema)

        # Fetch from DB and assert it was created
        access = await session.get(UserEventAccess, {"user_id": user.id, "event_id": event.id})
        assert access is not None
        assert access.user_id == user.id
        assert access.event_id == event.id
        assert access.otp_id == otp.id
        assert access.is_deleted is False

        # Try to create the same record again and expect failure
        with pytest.raises(ValueError) as exc_info:
            await service.create_user_event_access(schema)

        assert "already exists" in str(exc_info.value)
