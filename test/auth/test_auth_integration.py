import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient, ASGITransport
from services import AuthService, HostService
from database import AsyncSessionLocal
from models import Host
from schema import HostCreateSchema, LoginRequestSchema
from utils.utils import create_jwt, verify_jwt
import sys
import asyncio
import uuid
from uuid import uuid4
from datetime import datetime, timedelta

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)

@pytest.mark.asyncio
async def test_jwt_token_creation_and_verification():
    """Test JWT token creation and verification utilities"""
    test_data = {
        "user_id": str(uuid.uuid4()),
        "jti": str(uuid4()),
        "now": datetime.now(),
        "lifespan": timedelta(hours=1),
        "session_id": str(uuid4()),
        "remember_me": True,
        "issuer": "test_issuer",
        "audience": "test_audience"
    }

    # i tried to fix this sorry 

    # Create JWT token
    token = create_jwt(**test_data)
    assert isinstance(token, str)
    assert len(token) > 50  # JWT tokens are long
    
    # Verify JWT token
    decoded_user = verify_jwt(token)
    assert decoded_user == test_data





@pytest.mark.asyncio
async def test_password_hashing_consistency():
    """Test that password hashing is consistent between auth service and host repository"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        host_service = HostService(session)
        
        email = f"consistency_test_{uuid4()}@example.com"
        password = "consistencytest123"
        
        # Create host (uses repository hashing)
        host_create = HostCreateSchema(
            email=email,
            company_name="Consistency Test Company",
            password=password,
            created_at="2023-10-01T12:00:00Z"
        )
        
        created_host = await host_service.create_host(host_create)
        
        # Get the host with password included for testing
        host_with_password = await host_service.get_host_by_email(email, includePassword=True)
        
        # Verify auth service can validate the password hashed by repository
        is_valid = authn_service.verify_password(password, host_with_password.password_hash)
        assert is_valid is True
        
        # Verify wrong password fails
        is_invalid = authn_service.verify_password("wrongpassword", host_with_password.password_hash)
        assert is_invalid is False
        
        # Clean up
        await host_service.delete_host_by_id(created_host.id)


@pytest.mark.asyncio
async def test_authentication_with_special_characters():
    """Test authentication with special characters in email and password"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        host_service = HostService(session)
        
        # Email with special characters
        email = f"test+special.chars_{uuid4()}@example-domain.com"
        # Password with special characters
        password = "P@ssw0rd!#$%^&*()_+{}|:<>?[]\\;'\",./"
        
        host_create = HostCreateSchema(
            email=email,
            company_name="Special Chars Test Company",
            password=password,
            created_at="2023-10-01T12:00:00Z"
        )
        
        created_host = await host_service.create_host(host_create)
        assert created_host is not None
        
        # Test authentication
        authenticated_host = await authn_service.authenticate_host(email, password)
        assert authenticated_host is not None
        assert authenticated_host.email == email
        
        # Test login
        login_request = LoginRequestSchema(email=email, password=password)
        login_response = await authn_service.login_service(login_request)
        assert "access_token" in login_response
        
        # Clean up
        await host_service.delete_host_by_id(created_host.id)


@pytest.mark.asyncio
async def test_concurrent_authentication_requests():
    """Test multiple concurrent authentication requests"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        host_service = HostService(session)
        
        # Create multiple test hosts
        hosts_data = []
        for i in range(3):
            email = f"concurrent_test_{i}_{uuid4()}@example.com"
            password = f"concurrenttest{i}123"
            
            host_create = HostCreateSchema(
                email=email,
                company_name=f"Concurrent Test Company {i}",
                password=password,
                created_at="2023-10-01T12:00:00Z"
            )
            
            created_host = await host_service.create_host(host_create)
            hosts_data.append({
                "host": created_host,
                "email": email,
                "password": password
            })
        
        # Test concurrent logins
        async def login_host(host_data):
            login_request = LoginRequestSchema(
                email=host_data["email"],
                password=host_data["password"]
            )
            return await authn_service.login_service(login_request)
        
        # Execute concurrent logins
        import asyncio
        login_tasks = [login_host(host_data) for host_data in hosts_data]
        login_responses = await asyncio.gather(*login_tasks)
        
        # Verify all logins succeeded
        assert len(login_responses) == 3
        for i, response in enumerate(login_responses):
            assert "access_token" in response
            assert response["email"] == hosts_data[i]["email"]
        
        # Clean up
        for host_data in hosts_data:
            await host_service.delete_host_by_id(host_data["host"].id)


@pytest.mark.asyncio
async def test_authentication_edge_cases():
    """Test authentication edge cases and error conditions"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        host_service = HostService(session)
        
        # Test empty email
        with pytest.raises(Exception):
            await authn_service.authenticate_host("", "password")
        
        # Test empty password
        with pytest.raises(Exception):
            await authn_service.authenticate_host("test@example.com", "")
        
        # Test None values
        with pytest.raises(Exception):
            await authn_service.authenticate_host(None, "password")
        
        with pytest.raises(Exception):
            await authn_service.authenticate_host("test@example.com", None)


@pytest.mark.asyncio
async def test_host_sanitization_in_auth_responses():
    """Test that host objects returned by auth service have sanitized password_hash"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        host_service = HostService(session)
        
        email = f"sanitization_test_{uuid4()}@example.com"
        password = "sanitizationtest123"
        
        host_create = HostCreateSchema(
            email=email,
            company_name="Sanitization Test Company",
            password=password,
            created_at="2023-10-01T12:00:00Z"
        )
        
        created_host = await host_service.create_host(host_create)
        
        # Login and get current host
        login_request = LoginRequestSchema(email=email, password=password)
        login_response = await authn_service.login_service(login_request)
        
        token = login_response["access_token"]
        current_host = await authn_service.get_current_host_service(token)
        
        # Verify password_hash is None (sanitized)
        assert current_host.password_hash is None
        assert current_host.email == email
        assert current_host.company_name == "Sanitization Test Company"
        
        # Clean up
        await host_service.delete_host_by_id(created_host.id)


@pytest.mark.asyncio
async def test_authentication_performance():
    """Test authentication performance with password hashing"""
    async with AsyncSessionLocal() as session:
        authn_service = AuthService(session)
        host_service = HostService(session)
        
        email = f"performance_test_{uuid4()}@example.com"
        password = "performancetest123"
        
        # Create host
        host_create = HostCreateSchema(
            email=email,
            company_name="Performance Test Company",
            password=password,
            created_at="2023-10-01T12:00:00Z"
        )
        
        # Measure host creation time (includes password hashing)
        import time
        start_time = time.time()
        created_host = await host_service.create_host(host_create)
        creation_time = time.time() - start_time
        
        # Password hashing should take some time but not too long
        assert creation_time > 0.01  # At least 10ms (bcrypt is intentionally slow)
        assert creation_time < 5.0   # But not more than 5 seconds
        
        # Measure authentication time
        start_time = time.time()
        authenticated_host = await authn_service.authenticate_host(email, password)
        auth_time = time.time() - start_time
        
        assert authenticated_host is not None
        assert auth_time > 0.01  # At least 10ms
        assert auth_time < 5.0   # But not more than 5 seconds
        
        # Clean up
        await host_service.delete_host_by_id(created_host.id)


@pytest.mark.asyncio
async def test_auth_integration_with_existing_host_routes():
    """Test authentication integration with existing host CRUD routes"""
    email = f"integration_test_{uuid4()}@example.com"
    password = "integrationtest123"
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create host via API
        host_payload = {
            "email": email,
            "company_name": "Integration Test Company",
            "password": password,
            "created_at": "2023-10-01T12:00:00Z"
        }
        
        host_response = await client.post("/hosts/", json=host_payload)
        assert host_response.status_code == 201
        host_data = host_response.json()
        
        # Login using the created host
        login_payload = {"email": email, "password": password}
        login_response = await client.post("/auth/login", json=login_payload)
        assert login_response.status_code == 200
        login_data = login_response.json()
        
        # Use auth token to access host info
        headers = {"Authorization": f"Bearer {login_data['access_token']}"}
        me_response = await client.get("/auth/me", headers=headers)
        assert me_response.status_code == 200
        me_data = me_response.json()
        
        # Verify the host data matches
        assert me_data["email"] == host_data["email"]
        assert me_data["host_id"] == host_data["id"]
        
        # Access host by ID via existing route (should work without auth for now)
        host_by_id_response = await client.get(f"/hosts/by-id/{host_data['id']}")
        assert host_by_id_response.status_code == 200
        host_by_id_data = host_by_id_response.json()
        assert host_by_id_data["email"] == email
        
        # Clean up
        delete_response = await client.delete(f"/hosts/{host_data['id']}")
        assert delete_response.status_code == 204
