import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient, ASGITransport
from services  import UserService
from repository import UserRepository
from database import AsyncSessionLocal
from schema import UserCreateSchema
import uuid
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)
@pytest.mark.asyncio
async def test_create_user():
    async with AsyncSessionLocal() as session: # type: ignore
        repo = UserRepository(session)
        random = str (uuid.uuid4())
        # Test data
        user_data = UserCreateSchema(
            email=f"test{random}@example.com",
            password="hashed_password_123",
            name="Simon Test"
        )

        # Create new User
        new_user = await repo.create_user(user_data)
        
        # Assertions
        assert new_user is not None
        assert new_user.email == user_data.email 
        assert new_user.is_deleted is False
        assert new_user.is_active is True
        assert new_user.id is not None
        assert new_user.user_number > 0
        assert new_user.created_at is not None
        assert new_user.updated_at is not None
 