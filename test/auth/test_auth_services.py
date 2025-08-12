import bcrypt
import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient, ASGITransport
from services import AuthService, HostService
from database import AsyncSessionLocal
from models import Host
from schema import HostCreateSchema, LoginRequest
from utils.utils import verify_jwt
import sys
import asyncio
from uuid import uuid4
import uuid

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)

@pytest.mark.asyncio
async def test_hash_password():
    """Test password hashing functionality"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        
        password = "testpassword123"
        hashed = authn_service.hash_password(password)
        
        # Verify the hash is different from the original password
        assert hashed != password
        assert bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


@pytest.mark.asyncio
async def test_verify_password():
    """Test password verification functionality"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        
        password = "testpassword123"
        wrong_password = "wrongpassword"
        hashed = authn_service.hash_password(password)
        
        # Test correct password
        assert authn_service.verify_password(password, hashed) is True
        
        # Test wrong password
        assert authn_service.verify_password(wrong_password, hashed) is False


@pytest.mark.asyncio
async def test_authenticate_host_success():
    """Test successful host authentication"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        host_service = HostService(session)
        
        # Create a test host first
        email = f"auth_test_{uuid4()}@example.com"
        password = "testpassword123"
        
        host_create = HostCreateSchema(
            email=email,
            company_name="Test Auth Company",
            password=password,
            created_at="2023-10-01T12:00:00Z"
        )
        
        created_host = await host_service.create_host(host_create)
        assert created_host is not None
        
        # Test authentication with correct credentials
        authenticated_host = await authn_service.authenticate_host(email, password)
        assert authenticated_host is not None
        assert authenticated_host.email == email
        assert authenticated_host.company_name == "Test Auth Company"
        
        # Clean up
        await host_service.delete_host_by_id(created_host.id)


@pytest.mark.asyncio
async def test_authenticate_host_wrong_password():
    """Test host authentication with wrong password"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        host_service = HostService(session)
        
        # Create a test host first
        email = f"auth_test_{uuid4()}@example.com"
        password = "testpassword123"
        wrong_password = "wrongpassword"
        
        host_create = HostCreateSchema(
            email=email,
            company_name="Test Auth Company",
            password=password,
            created_at="2023-10-01T12:00:00Z"
        )
        
        created_host = await host_service.create_host(host_create)
        assert created_host is not None
        
        # Test authentication with wrong password
        authenticated_host = await authn_service.authenticate_host(email, wrong_password)
        assert authenticated_host is None
        
        # Clean up
        await host_service.delete_host_by_id(created_host.id)


@pytest.mark.asyncio
async def test_authenticate_host_nonexistent_email():
    """Test host authentication with non-existent email"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        
        # Test authentication with non-existent email
        authenticated_host = await authn_service.authenticate_host("nonexistent@example.com", "password")
        assert authenticated_host is None


@pytest.mark.asyncio
async def test_login_success():
    """Test successful login and JWT token generation"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        host_service = HostService(session)
        
        # Create a test host first
        email = f"auth_test_{uuid4()}@example.com"
        password = "testpassword123"
        
        host_create = HostCreateSchema(
            email=email,
            company_name="Test Auth Company",
            password=password,
            created_at="2023-10-01T12:00:00Z"
        )
        
        created_host = await host_service.create_host(host_create)
        assert created_host is not None
        
        # Test login
        login_request = LoginRequest(email=email, password=password)
        login_response = await authn_service.login(login_request)
        
        assert "access_token" in login_response
        assert login_response["token_type"] == "bearer"
        assert login_response["email"] == email
        
        # Verify JWT token is valid
        token = login_response["access_token"]
        decoded_user_id = verify_jwt(token)
        assert decoded_user_id == str(created_host.id)
        
        # Clean up
        await host_service.delete_host_by_id(created_host.id)


@pytest.mark.asyncio
async def test_login_invalid_credentials():
    """Test login with invalid credentials"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        
        # Test login with invalid credentials
        login_request = LoginRequest(email="nonexistent@example.com", password="wrongpassword")
        
        with pytest.raises(Exception):  # Should raise HTTPException
            await authn_service.login(login_request)


@pytest.mark.asyncio
async def test_get_current_host_success():
    """Test getting current host from valid JWT token"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        host_service = HostService(session)
        
        # Create a test host and login
        email = f"auth_test_{uuid4()}@example.com"
        password = "testpassword123"
        
        host_create = HostCreateSchema(
            email=email,
            company_name="Test Auth Company", 
            password=password,
            created_at="2023-10-01T12:00:00Z"
        )
        
        created_host = await host_service.create_host(host_create)
        login_request = LoginRequest(email=email, password=password)
        login_response = await authn_service.login(login_request)
        
        # Test get current host
        token = login_response["access_token"]
        current_host = await authn_service.get_current_host(token)
        
        assert current_host is not None
        assert current_host.email == email
        assert current_host.company_name == "Test Auth Company"
        assert current_host.password_hash is None  # Should be sanitized
        
        # Clean up
        await host_service.delete_host_by_id(created_host.id)


@pytest.mark.asyncio
async def test_get_current_host_invalid_token():
    """Test getting current host with invalid JWT token"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        
        # Test with invalid token
        with pytest.raises(Exception):  # Should raise HTTPException
            await authn_service.get_current_host("invalid.jwt.token")


@pytest.mark.asyncio
async def test_get_current_host_invalid_uuid():
    """Test getting current host with JWT containing invalid UUID"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        
        # Create a token with invalid UUID (this would be a malformed token scenario)
        from utils.utils import create_jwt
        invalid_token = create_jwt("not-a-valid-uuid")
        
        with pytest.raises(Exception):  # Should raise HTTPException due to invalid UUID
            await authn_service.get_current_host(invalid_token)


@pytest.mark.asyncio
async def test_get_current_host_nonexistent_host():
    """Test getting current host with JWT containing UUID of non-existent host"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        
        # Create a token with valid UUID format but non-existent host
        from utils.utils import create_jwt
        fake_uuid = str(uuid.uuid4())
        fake_token = create_jwt(fake_uuid)
        
        with pytest.raises(Exception):  # Should raise HTTPException due to host not found
            await authn_service.get_current_host(fake_token)


@pytest.mark.asyncio 
async def test_authn_service_integration():
    """Test complete authentication flow: create host -> login -> get current user"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        host_service = HostService(session)
        
        # Step 1: Create host (registration)
        email = f"auth_integration_{uuid4()}@example.com"
        password = "integrationtest123"
        
        host_create = HostCreateSchema(
            email=email,
            company_name="Integration Test Company",
            password=password,
            created_at="2023-10-01T12:00:00Z"
        )
        
        created_host = await host_service.create_host(host_create)
        assert created_host is not None
        assert created_host.email == email
        assert created_host.password_hash is None  # Should be sanitized in response
        
        # Step 2: Login
        login_request = LoginRequest(email=email, password=password)
        login_response = await authn_service.login(login_request)
        
        assert "access_token" in login_response
        assert login_response["token_type"] == "bearer"
        assert login_response["email"] == email
        
        # Step 3: Get current user using JWT
        token = login_response["access_token"]
        current_host = await authn_service.get_current_host(token)
        
        assert current_host.email == email
        assert current_host.company_name == "Integration Test Company"
        assert current_host.id == created_host.id
        assert current_host.password_hash is None  # Should be sanitized
        
        # Step 4: Clean up
        await host_service.delete_host_by_id(created_host.id)
