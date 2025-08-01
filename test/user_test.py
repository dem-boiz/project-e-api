import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient, ASGITransport
from services  import UserService
from database import AsyncSessionLocal
from models import User
import uuid
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)

def test_create_user():
    payload = {
        "email": "testuser@example.com" 
    }

    response = client.post("/users/", json=payload)
    assert response.status_code == 201
    print(response.json())
    assert response.json()["email"] == payload["email"]
    assert "id" in response.json()

def test_get_user_by_id():
    async def inner():
        test_email = f"test_{uuid.uuid4()}@example.com"
        
        async with AsyncSessionLocal() as session:
            # Create a new user
            new_user = User(email=test_email)
            session.add(new_user)
            await session.commit()
            await session.refresh(new_user)

            # Fetch user by ID
            service = UserService(session)
            fetched_user = await service.get_user_by_id(new_user.id)

            assert fetched_user is not None
            assert fetched_user.id == new_user.id
            assert fetched_user.email == new_user.email

    asyncio.run(inner())

def test_get_user_by_email():
    async def inner():
        test_email = f"test_{uuid.uuid4()}@example.com"
        
        async with AsyncSessionLocal() as session:
            # Create a new user
            new_user = User(email=test_email)
            session.add(new_user)
            await session.commit()
            await session.refresh(new_user)

            # Fetch user by ID
            service = UserService(session)
            fetched_user = await service.get_user_by_email(test_email)

            assert fetched_user is not None
            assert fetched_user.id == new_user.id
            assert fetched_user.email == new_user.email

    asyncio.run(inner())


@pytest.mark.asyncio
async def test_create_duplicate_user():
    user_data = {"email": "duplicate@example.com"}

    async with AsyncClient(app=app, base_url="http://test") as ac:
        # First creation should succeed
        response1 = await ac.post("/users/", json=user_data)
        assert response1.status_code == 201

        # Second creation should fail due to duplicate
        response2 = await ac.post("/users/", json=user_data)
        assert response2.status_code == 400  # or 409 depending on your implementation