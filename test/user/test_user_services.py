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
from uuid import uuid4
from schema import UserCreate

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)
@pytest.mark.asyncio
async def create_and_hard_delete_user():
    async with AsyncSessionLocal() as session:
        service = UserService(session)
        email = "testuser1@example.com"

        # Create new User
        userCreate = UserCreate(email=email)
        new_user = await service.create_user(userCreate)
        assert new_user is not None
        assert new_user.email == email
        assert new_user.id is not  None 
        
        # Clean up
        is_deleted = await service.hard_delete_user(new_user.id)
        assert is_deleted is True

@pytest.mark.asyncio
async def test_get_user_by_email():
    async with AsyncSessionLocal() as session:
        service = UserService(session)
        email = "testuser1@example.com"

        # Create new User
        userCreate = UserCreate(email=email)
        new_user = await service.create_user(userCreate)
        assert new_user is not None
        assert new_user.email == email
        assert new_user.id is not  None 
        assert new_user.is_deleted == False

        # Get User by email
        existing_user = await service.get_user_by_email(email)
        assert existing_user is not None
        assert existing_user.email == email 
        assert existing_user.id == new_user.id 
        assert existing_user.is_deleted == new_user.is_deleted
        
        # Clean up
        is_deleted = await service.hard_delete_user(new_user.id)
        assert is_deleted is True

@pytest.mark.asyncio
async def test_get_user_by_email():
    async with AsyncSessionLocal() as session:
        service = UserService(session)
        email = "testuser1@example.com"

        # Create new User
        userCreate = UserCreate(email=email)
        new_user = await service.create_user(userCreate)
        assert new_user is not None
        assert new_user.email == email
        assert new_user.id is not  None 
        assert new_user.is_deleted == False
        
        # Get User by email
        existing_user = await service.get_user_by_id(new_user.id)
        assert existing_user is not None
        assert existing_user.email == email 
        assert existing_user.id == new_user.id 
        assert existing_user.is_deleted == new_user.is_deleted
        
        # Clean up
        is_deleted = await service.hard_delete_user(new_user.id)
        assert is_deleted is True

@pytest.mark.asyncio
async def test_get_user_by_email():
    async with AsyncSessionLocal() as session:
        service = UserService(session)
        email = "testuser1@example.com"

        # Create new User
        userCreate = UserCreate(email=email)
        new_user = await service.create_user(userCreate)
        assert new_user is not None
        assert new_user.email == email
        assert new_user.id is not  None 
        assert new_user.is_deleted == False
        
        # Get User by email
        existing_user = await service.get_user_by_id(new_user.id)
        assert existing_user is not None
        assert existing_user.email == email 
        assert existing_user.id == new_user.id 
        assert existing_user.is_deleted == new_user.is_deleted
        
        # Clean up
        is_deleted = await service.hard_delete_user(new_user.id)
        assert is_deleted is True

@pytest.mark.asyncio
async def test_user_soft_delete():
    async with AsyncSessionLocal() as session:
        service = UserService(session)
        email = "testuser1@example.com"

        # Create new User
        userCreate = UserCreate(email=email)
        new_user = await service.create_user(userCreate)
        assert new_user is not None
        assert new_user.email == email
        assert new_user.id is not  None 
        assert new_user.is_deleted == False
        
        # Soft delete user
        await service.soft_delete_user(new_user.id)

        # Get user again and check is_deleted
        existing_user = await service.get_user_by_id(new_user.id)
        assert existing_user is not None
        assert existing_user.email == email 
        assert existing_user.id == new_user.id 
        assert existing_user.is_deleted == True
        
        # Clean up
        is_deleted = await service.hard_delete_user(new_user.id)
        assert is_deleted is True
 
@pytest.mark.asyncio
async def test_list_users():
    emails = [f"user{i}_{uuid4()}@example.com" for i in range(10)]

    async with AsyncSessionLocal() as session:
        service = UserService(session)
        created_users = []

        # Create 10 users
        for email in emails:
            user_create = UserCreate(email=email)
            user = await service.create_user(user_create)
            created_users.append(user)

        # Fetch all users
        users = await service.list_users()

        # Check that all created users are in the list
        user_ids = {user.id for user in users}
        for created_user in created_users:
            assert created_user.id in user_ids
            assert created_user.email in [u.email for u in users]

        # Clean up
        for user in created_users:
            await service.hard_delete_user(user.id)
