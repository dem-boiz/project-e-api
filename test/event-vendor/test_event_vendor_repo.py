import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient, ASGITransport 
from repository import EventVendorsRepository
from database import AsyncSessionLocal
from schema import EventVendorsCreateSchema
from datetime import datetime, date
import uuid
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)

@pytest.mark.asyncio
async def test_create_event_vendor():
    async with AsyncSessionLocal() as session: # type: ignore
        repo = EventVendorsRepository(session)
        
        # Test data - you may need to create valid event_id and user_id
        # or use existing ones from your test database
        test_event_id = uuid.uuid4()  # Replace with valid event_id
        test_user_id = uuid.uuid4()   # Replace with valid user_id
        test_date = datetime.now()
        
        event_vendor_data = EventVendorsCreateSchema(
            event_id=test_event_id,
            user_id=test_user_id,
            event_date=test_date
        )

        # Create new EventVendor
        new_event_vendor = await repo.create_event_vendor(event_vendor_data)
        
        # Assertions
        assert new_event_vendor is not None
        assert new_event_vendor.event_id == event_vendor_data.event_id
        assert new_event_vendor.user_id == event_vendor_data.user_id
        assert new_event_vendor.event_date == event_vendor_data.event_date
        assert new_event_vendor.added_at is not None
        assert isinstance(new_event_vendor.added_at, datetime)
        
        # Additional validation that the added_at timestamp is recent
        time_diff = datetime.now() - new_event_vendor.added_at
        assert time_diff.total_seconds() < 10  # Within 10 seconds