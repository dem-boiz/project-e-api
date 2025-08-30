from datetime import datetime 
import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient, ASGITransport
from services import  EventVendorsService
from database import AsyncSessionLocal
from models import User
from schema import EventVendorsCreateSchema
import uuid
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app) 

@pytest.mark.asyncio
async def test_create_event_vendor():
    # Test data - you may need to create valid event_id and user_id
    # or use existing ones from your test database
    test_event_id = uuid.uuid4()  # Replace with valid event_id
    test_user_id = uuid.uuid4()   # Replace with valid user_id
    test_date = datetime.now()
    
    event_vendor_data = {
        "event_id": f"{uuid.UUID('10000000-0000-0000-0000-000000000001')}",
        "user_id": f"{uuid.UUID('10000000-0000-0000-0000-000000000001')}",
        "event_date": f"{test_date}"
    }
    async with AsyncClient(base_url="http://localhost:8000") as client:
        response = await client.post("/event-vendors/", json=event_vendor_data)
    
    assert response.status_code == 201 


@pytest.mark.asyncio
async def test_create_and_get_event_vendor():
    """Test creating an event vendor and then retrieving it"""
    # Test data for creation
    test_event_id = uuid.UUID('10000000-0000-0000-0000-000000000001')
    test_user_id = uuid.UUID('10000000-0000-0000-0000-000000000001')
    test_date = datetime.now()
    
    event_vendor_data = {
        "event_id": str(test_event_id),
        "user_id": str(test_user_id),
        "event_date": f"{test_date}"
    }
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # First, create the event vendor
        create_response = await client.post("/event-vendors/", json=event_vendor_data)
        assert create_response.status_code == 201
        
        created_vendor = create_response.json()
        vendor_id = created_vendor.get("id")
        
        # Now test getting the event vendor
        # Assuming EventVendorSearchSchema uses query parameters
        search_params = { 
            "event_id": str(test_user_id)
        }
        
        get_response = await client.get("/event-vendors/event-id", params=search_params)
        assert get_response.status_code == 302  # As specified in your route
        
        retrieved_vendor = get_response.json()
        
        # Verify the retrieved data matches what we created
        assert len(retrieved_vendor) > 0
 

@pytest.mark.asyncio
async def test_update_event_vendor_description():
    """Test updating vendor description"""
    # First create an event vendor
    test_event_id = uuid.UUID('10000000-0000-0000-0000-000000000001')
    test_user_id = uuid.UUID('10000000-0000-0000-0000-000000000001')
    test_date = datetime.now()
    
    create_data = {
        "event_id": str(test_event_id),
        "user_id": str(test_user_id),
        "event_date": test_date.isoformat()
    }
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create the event vendor
        create_response = await client.post("/event-vendors/", json=create_data)
        assert create_response.status_code == 201
        
        # Update the vendor description
        update_data = {
            "user_id": str(test_user_id),
            "vendor_description": "Updated description for the vendor"
        }
        
        update_response = await client.patch("/event-vendors/", params=update_data)
        assert update_response.status_code == 202
        
        # Verify the response contains updated data
        updated_vendor = update_response.json()
        assert updated_vendor["user_id"] == str(test_user_id)
        # Verify description was updated (if included in response schema)
        if "vendor_description" in updated_vendor:
            assert updated_vendor["vendor_description"] == "Updated description for the vendor"
