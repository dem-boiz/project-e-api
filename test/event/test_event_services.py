import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient, ASGITransport
from services import EventService 
from schema import EventCreateSchema, EventUpdateSchema
from database import AsyncSessionLocal
from models import Event
from uuid import UUID, uuid4
from datetime import datetime, timedelta
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)

@pytest.mark.asyncio
async def test_create_event_success():
    async with AsyncSessionLocal() as session:
        service = EventService(session)
 
        # Ideally, you’d mock EventRepository methods or set up the test DB with required records
        event_data = EventCreateSchema(
            name="Awesome Event",
            host_id="00000000-0000-0000-0000-000000000001",
            datetime=(datetime.now() + timedelta(days=1)).isoformat(),
            location="Test Venue",
            description="This is a test description for the event.", 
        ) 
          

        event = await service.create_event_service(event_data)

        assert event is not None
        assert isinstance(event, Event)
        assert event.name == event_data.name
        assert event.host_id == event_data.host_id
        assert event.description == event_data.description
        assert event.location == event_data.location 

        await service.delete_event_service(event.id)  # Clean up after test

@pytest.mark.asyncio
async def test_get_event_by_id_success():
    async with AsyncSessionLocal() as session:
        service = EventService(session)

        # Create a test event first
        event_data = EventCreateSchema(
            name="Test Event for Get",
            host_id=UUID("00000000-0000-0000-0000-000000000001"),
            datetime=(datetime.now() + timedelta(days=1)).isoformat(),
            location="Test Location",
            description="Test event description for get by ID.",
            start_time="10:00",
            end_time="12:00"
        )

        created_event = await service.create_event_service(event_data)

        # Now try to retrieve the event by ID
        fetched_event = await service.get_event_by_id_service(created_event.id)

        assert fetched_event is not None
        assert isinstance(fetched_event, Event)
        assert fetched_event.id == created_event.id
        assert fetched_event.name == created_event.name
        assert fetched_event.location == created_event.location

        # Optional cleanup (if your service supports deleting)
        await service.repo.delete_event(created_event.id)

@pytest.mark.asyncio
async def test_get_event_by_name_success():
    async with AsyncSessionLocal() as session:
        service = EventService(session)

        # Create a test event first
        event_data = EventCreateSchema(
            name="Unique Test Event Name",
            host_id=UUID("00000000-0000-0000-0000-000000000001"),
            datetime=(datetime.now() + timedelta(days=1)).isoformat(),
            location="Get Name Location",
            description="Get event by name test description.",
            start_time="13:00",
            end_time="15:00"
        )

        created_event = await service.create_event_service(event_data)

        # Now try to retrieve the event by name
        fetched_event = await service.get_event_by_name_service(event_data.name)

        assert fetched_event is not None
        assert isinstance(fetched_event, Event)
        assert fetched_event.name == event_data.name
        assert fetched_event.host_id == event_data.host_id
        assert fetched_event.location == event_data.location
        assert fetched_event.description == event_data.description

        # Optional cleanup if supported
        await service.repo.delete_event(created_event.id)

@pytest.mark.asyncio
async def test_get_all_events():
    async with AsyncSessionLocal() as session:
        service = EventService(session)

        # Create one or more events
        event_data_1 = EventCreateSchema(
            name="First Event",
            host_id=UUID("00000000-0000-0000-0000-000000000001"),
            datetime=(datetime.now() + timedelta(days=2)).isoformat(),
            location="Event Location One",
            description="Description for first event.",
            start_time="09:00",
            end_time="11:00"
        )

        event_data_2 = EventCreateSchema(
            name="Second Event",
            host_id=UUID("00000000-0000-0000-0000-000000000001"),
            datetime=(datetime.now() + timedelta(days=3)).isoformat(),
            location="Event Location Two",
            description="Description for second event.",
            start_time="14:00",
            end_time="16:00"
        )

        created_event_1 = await service.create_event_service(event_data_1)
        created_event_2 = await service.create_event_service(event_data_2)

        # Retrieve all events
        all_events = await service.get_all_events_service()

        assert isinstance(all_events, list)
        assert len(all_events) >= 2

        # Ensure both created events are in the returned list
        event_names = [event.name for event in all_events]
        assert created_event_1.name in event_names
        assert created_event_2.name in event_names

        # Optional cleanup
        await service.repo.delete_event(created_event_1.id)
        await service.repo.delete_event(created_event_2.id)

@pytest.mark.asyncio
async def test_update_event_success():
    async with AsyncSessionLocal() as session:
        service = EventService(session)

        # Step 1: Create an event to be updated
        event_data = EventCreateSchema(
            name="Original Event Name",
            host_id=UUID("00000000-0000-0000-0000-000000000001"),
            datetime=(datetime.now() + timedelta(days=2)).isoformat(),
            location="Initial Location",
            description="Initial description for the event.",
            start_time="10:00",
            end_time="12:00"
        )

        created_event = await service.create_event_service(event_data)

        # Step 2: Prepare updated data
        update_data = EventUpdateSchema(
            name="Updated Event Name",
            location="Updated Location",
            description="Updated event description."
        )

        # Step 3: Call update_event_service
        updated_event = await service.update_event_service(created_event.id, update_data)

        # Step 4: Assert changes took effect
        assert updated_event is not None
        assert isinstance(updated_event, Event)
        assert updated_event.id == created_event.id
        assert updated_event.name == update_data.name
        assert updated_event.location == update_data.location
        assert updated_event.description == update_data.description

        # Optional cleanup
        await service.repo.delete_event(created_event.id)