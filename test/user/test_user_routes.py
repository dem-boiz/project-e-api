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
async def test_create_user():
    user_data = { 
        "email": f"{str(uuid.uuid4())}@example.com",   
        "password": "password123",
        "name": "Simon Test"
    }
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        response = await client.post("/users/", json=user_data)
    
    assert response.status_code == 201 