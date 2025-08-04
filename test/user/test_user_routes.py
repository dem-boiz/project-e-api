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

@pytest.mark.asyncio
async def test_create_and_hard_delete_user():
    payload = {"email": "testuser@example.com"}

    async with AsyncClient(base_url="http://localhost:8000") as client:
        response = await client.post("/users/create", json=payload)

        assert response.status_code == 201
        data = response.json()
        print(data)
        assert data["email"] == payload["email"]
        assert "id" in data

         
        # Hard delete user using your /hard-delete/by-id
        delete_url = f"/users/delete/by-id"
        delete_response = await client.delete(delete_url, params={"user_id": data["id"]})
        print(delete_url)
        assert delete_response.status_code == 204

@pytest.mark.asyncio
async def test_get_user_by_id():
    payload = {"email": "testuser@example.com"}

    async with AsyncClient(base_url="http://localhost:8000") as client:
        
        create_response = await client.post("/users/create", json=payload)

        assert create_response.status_code == 201
        data = create_response.json()
        print(data)
        assert data["email"] == payload["email"]
        assert "id" in data

        get_response = await client.get("/users/get/by-id/{user_id}".format(user_id=data["id"]))

        assert get_response.status_code == 200
        data = get_response.json() 
        assert data["email"] == payload["email"]
        assert "id" in data

         
        # Hard delete user using your /hard-delete/by-id
        delete_url = f"/users/delete/by-id"
        delete_response = await client.delete(delete_url, params={"user_id": data["id"]})
        print(delete_url)
        assert delete_response.status_code == 204

@pytest.mark.asyncio
async def test_get_user_by_email():
    payload = {"email": "testuser@example.com"}

    async with AsyncClient(base_url="http://localhost:8000") as client:
        
        create_response = await client.post("/users/create", json=payload)

        assert create_response.status_code == 201
        data = create_response.json()
        print(data)
        assert data["email"] == payload["email"]
        assert "id" in data

        get_response = await client.get("/users/get/by-email/{email}".format(email=data["email"]))

        assert get_response.status_code == 200
        data = get_response.json() 
        assert data["email"] == payload["email"]
        assert "id" in data

         
        # Hard delete user using your /hard-delete/by-id
        delete_url = f"/users/delete/by-id"
        delete_response = await client.delete(delete_url, params={"user_id": data["id"]})
        print(delete_url)
        assert delete_response.status_code == 204

 