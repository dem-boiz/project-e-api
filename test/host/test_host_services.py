import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException
from main import app
from httpx import AsyncClient, ASGITransport
from services import HostService
from database import AsyncSessionLocal
from models import Host
from schema import HostCreateSchema, HostUpdateSchema
import sys
import asyncio
from uuid import uuid4

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)

@pytest.mark.asyncio
async def test_create_and_delete_host():
    async with AsyncSessionLocal() as session:
        service = HostService(session)
        email = f"testhost_{uuid4()}@example.com"
        password = "securepassword"
        company_name = "Test Company"
        date = "2023-10-01T12:00:00Z"

        # Create the host
        host_create = HostCreateSchema(
            email=email,
            company_name=company_name,
            password_hash=password,
            created_at=date
        )
        new_host = await service.create_host(host_create)

        # Assertions after creation
        assert new_host is not None
        assert new_host.email == email
        assert new_host.id is not None

        # Delete the host
        is_deleted = await service.delete_host_by_id(new_host.id)

        # Assertions after deletion
        assert is_deleted is True

@pytest.mark.asyncio
async def test_get_host_by_email():
    async with AsyncSessionLocal() as session:
        service = HostService(session)
        email = f"testhost_{uuid4()}@example.com"
        password = "securepassword"
        company_name = "Test Company"
        date = "2023-10-01T12:00:00Z"

        # Create a host
        host_create = HostCreateSchema(
            email=email,
            company_name=company_name,
            password_hash=password,
            created_at=date
        )
        new_host = await service.create_host(host_create)

        # Retrieve host by email
        fetched_host = await service.get_host_by_email(email)

        # Assertions
        assert fetched_host is not None
        assert fetched_host.email == email
        assert fetched_host.id == new_host.id

        # Clean up
        is_deleted = await service.repo.delete_host_by_id(new_host.id)
        assert is_deleted is True

        # Test 404 case after deletion
        with pytest.raises(HTTPException) as exc_info:
            await service.get_host_by_email(email)

        assert exc_info.value.status_code == 404
        assert exc_info.value.detail == "Host not found"

@pytest.mark.asyncio
async def test_get_host_by_id():
    async with AsyncSessionLocal() as session:
        service = HostService(session)
        email = f"testhost_{uuid4()}@example.com"
        password = "securepassword"
        company_name = "Test Company"
        date = "2023-10-01T12:00:00Z"

        # Create a host
        host_create = HostCreateSchema(
            email=email,
            company_name=company_name,
            password_hash=password,
            created_at=date
        )
        new_host = await service.create_host(host_create)

        # Retrieve host by id
        fetched_host = await service.get_host_by_id(new_host.id)

        # Assertions for successful fetch
        assert fetched_host is not None
        assert fetched_host.id == new_host.id
        assert fetched_host.email == email

        # Clean up
        is_deleted = await service.repo.delete_host_by_id(new_host.id)
        assert is_deleted is True

        # Test 404 case after deletion
        with pytest.raises(HTTPException) as exc_info:
            await service.get_host_by_id(new_host.id)

        assert exc_info.value.status_code == 404
        assert exc_info.value.detail == "Host not found"


@pytest.mark.asyncio
async def test_update_host_service():
    async with AsyncSessionLocal() as session:
        service = HostService(session)
        email = f"testhost_{uuid4()}@example.com"
        password = "securepassword"
        company_name = "Test Company"
        date = "2023-10-01T12:00:00Z"

        # Create a host
        host_create = HostCreateSchema(
            email=email,
            company_name=company_name,
            password_hash=password,
            created_at=date
        )
        new_host = await service.create_host(host_create)

        # Prepare update data
        new_company_name = "Updated Company"
        new_email = f"updated_{uuid4()}@example.com"
        update_data = HostUpdateSchema(
            company_name=new_company_name,
            email=new_email
        )

        # Perform update
        updated_host = await service.update_host_service(new_host.id, update_data)

        # Assertions after update
        assert updated_host is not None
        assert updated_host.id == new_host.id
        assert updated_host.company_name == new_company_name
        assert updated_host.email == new_email

        # Clean up
        is_deleted = await service.repo.delete_host_by_id(new_host.id)
        assert is_deleted is True

        # Test 404 case after deletion
        with pytest.raises(ValueError) as exc_info:
            await service.update_host_service(new_host.id, update_data)

        assert str(exc_info.value) == "Host with the specified ID does not exist."