import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient, ASGITransport
from services  import UserService
from repository import UserRepository
from database import AsyncSessionLocal
from models import User
import uuid
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)
@pytest.mark.asyncio
async def test_delete_user_by_id():
    async with AsyncSessionLocal() as session:
        repo = UserRepository(session)
        email = "testuser1@example.com"

        # Create new User
        new_user = await repo.create_user(email)
        assert new_user is not None
        assert new_user.email == email
        assert new_user.id is not  None 
        assert new_user.is_deleted == False

        # Clean up
        is_deleted = await repo.delete_user_by_id(new_user.id)
        assert is_deleted is True

@pytest.mark.asyncio
async def test_delete_user_by_email():
    async with AsyncSessionLocal() as session:
        repo = UserRepository(session)
        email = "testuser1@example.com"

        # Create new User
        new_user = await repo.create_user(email)
        assert new_user is not None
        assert new_user.email == email
        assert new_user.id is not  None  
        assert new_user.is_deleted == False

        # Clean up
        is_deleted = await repo.delete_user_by_email(email)
        assert is_deleted is True

@pytest.mark.asyncio
async def test_create_user():
    async with AsyncSessionLocal() as session:
        repo = UserRepository(session)
        email = "testuser1@example.com"

        # Create new User
        new_user = await repo.create_user(email)
        assert new_user is not None
        assert new_user.email == email
        assert new_user.is_deleted == False

        # Clean up
        is_deleted = await repo.delete_user_by_email(email)
        assert is_deleted is True

@pytest.mark.asyncio
async def test_get_user_by_id():
    async with AsyncSessionLocal() as session:
        repo = UserRepository(session)
        email = "testuser1@example.com"

        # Create new User
        new_user = await repo.create_user(email)
        assert new_user is not None
        assert new_user.email == email
        assert new_user.id is not  None
        assert new_user.is_deleted == False

        # Get new User by ID
        existing_user = await repo.get_user_by_id(new_user.id)
        assert existing_user is not None 

        # Clean up
        is_deleted = await repo.delete_user_by_id(new_user.id)
        assert is_deleted is True



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
            assert new_user.is_deleted == False
    asyncio.run(inner()) 

