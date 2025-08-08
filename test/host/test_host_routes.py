import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient
from services import HostService
from database import AsyncSessionLocal
from schema import HostCreateSchema
import uuid
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)

@pytest.mark.asyncio
async def test_create_host_route():
    async with AsyncSessionLocal() as session:
        service = HostService(session)
        email = f"testhost_{uuid.uuid4()}@example.com"
        password = "securepassword"
        company_name = "Test Company"
        date = "2023-10-01T12:00:00Z"

        # Prepare the host create schema as dict to send in POST
        host_data = { 
            "email": email,
            "company_name": company_name,
            "password": password,
            "created_at": date
        }

        # Use httpx AsyncClient to send request to the FastAPI app
        async with AsyncClient(base_url="http://127.0.0.1:8000") as ac:
            response = await ac.post("/hosts/", json=host_data)

        assert response.status_code == 201
        returned = response.json()
        assert returned["email"] == email
        assert returned["company_name"] == company_name

        # Clean up: delete the host created
        new_host_id = returned.get("id")
        if new_host_id:
            is_deleted = await service.repo.delete_host_by_id(uuid.UUID(new_host_id))
            assert is_deleted is True


@pytest.mark.asyncio
async def test_create_and_delete_host():
    async with AsyncClient(base_url="http://127.0.0.1:8000") as client:
        # Step 1: Create a new host
        email = f"testhost_{uuid.uuid4()}@example.com"
        password = "securepassword"
        company_name = "Test Company"
        date = "2023-10-01T12:00:00Z"

        # Prepare the host create schema as dict to send in POST
        payload = { 
            "email": email,
            "company_name": company_name,
            "password": password,
            "created_at": date
        }
        create_response = await client.post("/hosts/", json=payload)

        assert create_response.status_code == 201
        data = create_response.json()
        assert data["email"] == payload["email"]
        assert "id" in data

        host_id = data["id"]

        # Step 2: Delete the host using their ID
        delete_response = await client.delete(f"/hosts/{host_id}")
        assert delete_response.status_code == 204

        # Step 3 (Optional): Try deleting again to check 404
        delete_again_response = await client.delete(f"/hosts/{host_id}")
        assert delete_again_response.status_code == 404

@pytest.mark.asyncio
async def test_get_host_by_id():
    async with AsyncClient(base_url="http://127.0.0.1:8000") as client:
        # Step 1: Create a new host
        email = f"testhost_{uuid.uuid4()}@example.com"
        password = "securepassword"
        company_name = "Test Company"
        date = "2023-10-01T12:00:00Z"

        payload = {
            "email": email,
            "company_name": company_name,
            "password": password,
            "created_at": date
        }

        create_response = await client.post("/hosts/", json=payload)
        assert create_response.status_code == 201
        created_data = create_response.json()
        assert "id" in created_data

        host_id = created_data["id"]

        # Step 2: Fetch the host by ID
        get_response = await client.get(f"/hosts/by-id/{host_id}")
        assert get_response.status_code == 200
        get_data = get_response.json()
        assert get_data["id"] == host_id
        assert get_data["email"] == email
        assert get_data["company_name"] == company_name

        # Step 3: Delete the host to clean up
        delete_response = await client.delete(f"/hosts/{host_id}")
        assert delete_response.status_code == 204

@pytest.mark.asyncio
async def test_get_host_by_email():
    async with AsyncClient(base_url="http://127.0.0.1:8000") as client:
        # Step 1: Create a new host
        email = f"testhost_{uuid.uuid4()}@example.com"
        password = "securepassword"
        company_name = "Test Company"
        date = "2023-10-01T12:00:00Z"

        payload = {
            "email": email,
            "company_name": company_name,
            "password": password,
            "created_at": date
        }

        create_response = await client.post("/hosts/", json=payload)
        assert create_response.status_code == 201
        created_data = create_response.json()
        assert "id" in created_data

        # Step 2: Fetch the host by email
        get_response = await client.get(f"/hosts/by-email/{email}")
        assert get_response.status_code == 200
        get_data = get_response.json()
        assert get_data["email"] == email
        assert get_data["company_name"] == company_name
        assert "id" in get_data

        host_id = get_data["id"]

        # Step 3: Delete the host to clean up
        delete_response = await client.delete(f"/hosts/{host_id}")
        assert delete_response.status_code == 204

@pytest.mark.asyncio
async def test_update_host():
    async with AsyncClient(base_url="http://127.0.0.1:8000") as client:
        # Step 1: Create a new host
        email = f"testhost_{uuid.uuid4()}@example.com"
        password = "securepassword"
        company_name = "Original Company"
        date = "2023-10-01T12:00:00Z"

        payload = {
            "email": email,
            "company_name": company_name,
            "password": password,
            "created_at": date
        }

        create_response = await client.post("/hosts/", json=payload)
        assert create_response.status_code == 201
        created_data = create_response.json()
        host_id = created_data["id"]

        # Step 2: Prepare update data (example: update company name)
        update_payload = {
            "company_name": "Updated Company"
        }

        # Step 3: Send PATCH request to update the host
        update_response = await client.patch(f"/hosts/{host_id}", json=update_payload)
        assert update_response.status_code == 200

        updated_data = update_response.json()
        assert updated_data["id"] == host_id
        assert updated_data["company_name"] == "Updated Company"
        assert updated_data["email"] == email  # unchanged
        # TODO Update this test to handle hashed password?
        assert "password_hash" in updated_data  # still present

        # Step 4: Clean up by deleting the host
        delete_response = await client.delete(f"/hosts/{host_id}")
        assert delete_response.status_code == 204