import pytest
from httpx import AsyncClient
from datetime import datetime, timedelta

@pytest.mark.asyncio
async def test_create_and_delete_event():
    payload = {
        "name": "Test Event from Route",
        "host_id": "00000000-0000-0000-0000-000000000001",
        "datetime": (datetime.now() + timedelta(days=1)).isoformat(),
        "location": "Test Event Venue",
        "description": "This is a test event created via route.",
        "start_time": "10:00",
        "end_time": "12:00"
    }

    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create event via POST route
        response = await client.post("/events", json=payload)
        
        assert response.status_code == 201
        data = response.json()
        print("Create Event Response:", data)

        assert data["name"] == payload["name"]
        assert data["host_id"] == payload["host_id"]
        assert data["location"] == payload["location"]
        assert data["description"] == payload["description"]
        assert "id" in data

        # Delete the event to clean up after test
        delete_response = await client.delete(f"/events/{data['id']}")
        print("Delete Event Response Code:", delete_response.status_code)
        assert delete_response.status_code == 204

@pytest.mark.asyncio
async def test_get_events():
    async with AsyncClient(base_url="http://localhost:8000") as client:
        response = await client.get("/events")

        assert response.status_code == 200

        data = response.json()
        print("Get Events Response:", data)

        assert isinstance(data, list)  # The endpoint should return a list

        if data:
            event = data[0]
            assert "id" in event
            assert "name" in event
            assert "host_id" in event
            assert "location" in event
            assert "description" in event

@pytest.mark.asyncio
async def test_get_event_by_id():
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # First create an event to retrieve
        payload = {
            "name": "Test Event from Route",
            "host_id": "00000000-0000-0000-0000-000000000001",
            "datetime": (datetime.now() + timedelta(days=1)).isoformat(),
            "location": "Test Event Venue",
            "description": "This is a test event created via route.",
            "start_time": "10:00",
            "end_time": "12:00"
        }

        create_response = await client.post("/events", json=payload)
        assert create_response.status_code == 201
        created_event = create_response.json()
        event_id = created_event["id"]

        # Now retrieve the event by ID
        get_response = await client.get(f"/events/get/by-id/{event_id}")
        assert get_response.status_code == 200

        event = get_response.json()
        print("Get Event By ID Response:", event)

        assert event["id"] == event_id
        assert event["name"] == payload["name"]
        assert event["host_id"] == payload["host_id"]
        assert event["location"] == payload["location"]
        assert event["description"] == payload["description"]


@pytest.mark.asyncio
async def test_get_event_by_name():
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create a new event to later retrieve by name
        payload = {
            "name": "Test Event from Route",
            "host_id": "00000000-0000-0000-0000-000000000001",
            "datetime": (datetime.now() + timedelta(days=1)).isoformat(),
            "location": "Test Event Venue",
            "description": "This is a test event created via route.",
            "start_time": "10:00",
            "end_time": "12:00"
        }

        create_response = await client.post("/events", json=payload)
        assert create_response.status_code == 201
        created_event = create_response.json()

        # Retrieve event by name
        name = payload["name"]
        get_response = await client.get(f"/events/get/by-name/{name}")
        assert get_response.status_code == 200

        event = get_response.json()
        print("Get Event By Name Response:", event)

        assert event["name"] == payload["name"]
        assert event["host_id"] == payload["host_id"]
        assert event["location"] == payload["location"]
        assert event["description"] == payload["description"]


@pytest.mark.asyncio
async def test_patch_update_event():
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # First, create an event to update
        create_payload = {
            "name": "Event To Update",
            "host_id": "00000000-0000-0000-0000-000000000001",
            "datetime": (datetime.now() + timedelta(days=1)).isoformat(),
            "location": "Initial Location",
            "description": "Initial description",
            "start_time": "10:00",
            "end_time": "12:00"
        }

        create_response = await client.post("/events", json=create_payload)
        assert create_response.status_code == 201
        created_event = create_response.json()
        event_id = created_event["id"]

        # Prepare patch/update payload (partial or full)
        update_payload = {
            "name": "Updated Event Name",
            "location": "Updated Location",
            "description": "Updated description"
        }

        # Call PATCH endpoint to update event
        patch_response = await client.patch(f"/events/{event_id}", json=update_payload)
        assert patch_response.status_code == 200
        updated_event = patch_response.json()

        # Assert updated fields
        assert updated_event["id"] == event_id
        assert updated_event["name"] == update_payload["name"]
        assert updated_event["location"] == update_payload["location"]
        assert updated_event["description"] == update_payload["description"]

        # Cleanup (delete event)
        delete_response = await client.delete(f"/events/{event_id}")
        assert delete_response.status_code == 204