import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient, ASGITransport
from services import HostService
from database import AsyncSessionLocal
from models import Host
from schema import HostCreateSchema
import sys
import asyncio
import json
from uuid import uuid4

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)

@pytest.mark.asyncio
async def test_logout_route_success():
    """Test POST /auth/logout after logging in"""
    email = f"route_test_{uuid4()}@example.com"
    password = "routetest123"

    host_payload = {
        "email": email,
        "company_name": "Route Test Company",
        "password": password,
        "created_at": "2023-10-01T12:00:00Z"
    }

    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create host
        host_response = await client.post("/hosts/", json=host_payload)
        assert host_response.status_code == 201
        host_data = host_response.json()

        # Login to get token & cookies
        login_payload = {
            "email": email,
            "password": password,
            "rememberMe": False
        }
        login_response = await client.post("/auth/login", json=login_payload)
        assert login_response.status_code == 200

        cookies = login_response.cookies

        # Call logout endpoint
        logout_response = await client.post("/auth/logout", cookies=cookies)
        assert logout_response.status_code == 200
        assert logout_response.json()["message"] == "Logged out successfully"

        # Clean up - delete the host
        delete_response = await client.delete(f"/hosts/{host_data['id']}")
        assert delete_response.status_code == 204
        
@pytest.mark.asyncio
async def test_login_route_success():
    """Test POST /auth/login with valid credentials"""
    # Create a test host first
    email = f"route_test_{uuid4()}@example.com"
    password = "routetest123"
    
    # Create host via direct API
    host_payload = {
        "email": email,
        "company_name": "Route Test Company",
        "password": password,
        "created_at": "2023-10-01T12:00:00Z"
    }
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create host
        host_response = await client.post("/hosts/", json=host_payload)
        assert host_response.status_code == 201
        host_data = host_response.json()
        
        # Test login
        login_payload = {
            "email": email,
            "password": password
        }
        
        login_response = await client.post("/auth/login", json=login_payload)
        assert login_response.status_code == 200
        
        login_data = login_response.json()
        assert "access_token" in login_data
        assert login_data["token_type"] == "bearer"
        assert login_data["email"] == email
        assert len(login_data["access_token"]) > 50  # JWT tokens are long
        
        # Clean up - delete the host
        delete_response = await client.delete(f"/hosts/{host_data['id']}")
        assert delete_response.status_code == 204


@pytest.mark.asyncio
async def test_login_route_invalid_email():
    """Test POST /auth/login with invalid email"""
    login_payload = {
        "email": "nonexistent@example.com",
        "password": "anypassword"
    }
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        login_response = await client.post("/auth/login", json=login_payload)
        assert login_response.status_code == 401
        
        error_data = login_response.json()
        assert "detail" in error_data
        assert "Invalid email or password" in error_data["detail"]


@pytest.mark.asyncio
async def test_login_route_invalid_password():
    """Test POST /auth/login with valid email but wrong password"""
    # Create a test host first
    email = f"route_test_{uuid4()}@example.com"
    password = "correctpassword"
    wrong_password = "wrongpassword"
    
    host_payload = {
        "email": email,
        "company_name": "Route Test Company",
        "password": password,
        "created_at": "2023-10-01T12:00:00Z"
    }
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create host
        host_response = await client.post("/hosts/", json=host_payload)
        assert host_response.status_code == 201
        host_data = host_response.json()
        
        # Test login with wrong password
        login_payload = {
            "email": email,
            "password": wrong_password
        }
        
        login_response = await client.post("/auth/login", json=login_payload)
        assert login_response.status_code == 401
        
        error_data = login_response.json()
        assert "detail" in error_data
        assert "Invalid email or password" in error_data["detail"]
        
        # Clean up
        delete_response = await client.delete(f"/hosts/{host_data['id']}")
        assert delete_response.status_code == 204


@pytest.mark.asyncio 
async def test_login_route_missing_fields():
    """Test POST /auth/login with missing required fields"""
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Missing password
        incomplete_payload = {"email": "test@example.com"}
        response = await client.post("/auth/login", json=incomplete_payload)
        assert response.status_code == 422  # Validation error
        
        # Missing email
        incomplete_payload = {"password": "password123"}
        response = await client.post("/auth/login", json=incomplete_payload)
        assert response.status_code == 422  # Validation error
        
        # Empty payload
        response = await client.post("/auth/login", json={})
        assert response.status_code == 422  # Validation error


@pytest.mark.asyncio
async def test_get_current_user_route_success():
    """Test GET /auth/me with valid JWT token"""
    # Create host and login first
    email = f"route_test_{uuid4()}@example.com"
    password = "routetest123"
    
    host_payload = {
        "email": email,
        "company_name": "Route Test Company",
        "password": password,
        "created_at": "2023-10-01T12:00:00Z"
    }
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create host
        host_response = await client.post("/hosts/", json=host_payload)
        assert host_response.status_code == 201
        host_data = host_response.json()
        
        # Login to get token
        login_payload = {"email": email, "password": password}
        login_response = await client.post("/auth/login", json=login_payload)
        assert login_response.status_code == 200
        
        login_data = login_response.json()
        token = login_data["access_token"]
        
        # Test /auth/me endpoint
        headers = {"Authorization": f"Bearer {token}"}
        me_response = await client.get("/auth/me", headers=headers)
        assert me_response.status_code == 200
        
        me_data = me_response.json()
        assert me_data["email"] == email
        assert me_data["host_id"] == host_data["id"]
        
        # Clean up
        delete_response = await client.delete(f"/hosts/{host_data['id']}")
        assert delete_response.status_code == 204


@pytest.mark.asyncio
async def test_get_current_user_route_no_token():
    """Test GET /auth/me without authorization header"""
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        me_response = await client.get("/auth/me")
        assert me_response.status_code == 403  # Forbidden - no auth header


@pytest.mark.asyncio
async def test_get_current_user_route_invalid_token():
    """Test GET /auth/me with invalid JWT token"""
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        headers = {"Authorization": "Bearer invalid.jwt.token"}
        me_response = await client.get("/auth/me", headers=headers)
        assert me_response.status_code == 401  # Unauthorized

@pytest.mark.asyncio
async def test_refresh_token_rotates_access_and_csrf():
    """Test that /refresh returns new access token and CSRF token"""
    email = f"refresh_{uuid4()}@example.com"
    password = "TestPassword123!"

    # Create host first
    host_payload = {
        "email": email,
        "company_name": "Refresh Test Company", 
        "password": password,
        "created_at": "2023-10-01T12:00:00Z"
    }

    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create host
        host_resp = await client.post("/hosts/", json=host_payload)
        assert host_resp.status_code == 201

        # Login to get tokens
        login_payload = {"email": email, "password": password, "rememberMe": True}
        login_resp = await client.post("/auth/login", json=login_payload)
        assert login_resp.status_code == 200
        
        # DEBUG: Print what we got from login
        print(f"Login response body: {login_resp.json()}")
        print(f"Login cookies: {dict(login_resp.cookies)}")

        refresh_cookie = login_resp.cookies.get("refresh_token")
        assert refresh_cookie is not None
        
        # Get CSRF token from response
        login_data = login_resp.json()
        csrf_token = login_data.get("csrf_token")
        
        # DEBUG: Check if we have CSRF token
        print(f"CSRF token from login: {csrf_token}")
        
        if not csrf_token:
            print("WARNING: No CSRF token in login response!")
            # Try without CSRF to see the error
            refresh_resp = await client.post(
                "/auth/refresh", 
                cookies={"refresh_token": refresh_cookie}
            )
            print(f"Error response: {refresh_resp.json()}")
            assert False, "No CSRF token in login response"
        
        # Check for CSRF cookie
        csrf_cookie = login_resp.cookies.get("csrf_token") or csrf_token
        
        # Call refresh with CSRF
        refresh_resp = await client.post(
            "/auth/refresh",
            cookies={
                "refresh_token": refresh_cookie,
                "csrf_token": csrf_cookie
            },
            headers={"X-CSRF-Token": csrf_cookie}
        )
        
        # DEBUG: If failed, print error
        if refresh_resp.status_code != 200:
            print(f"Refresh failed with status {refresh_resp.status_code}")
            print(f"Error: {refresh_resp.json()}")
        
        assert refresh_resp.status_code == 200

@pytest.mark.asyncio
async def test_get_current_user_route_malformed_header():
    """Test GET /auth/me with malformed authorization header"""
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Missing "Bearer" prefix
        headers = {"Authorization": "some-token"}
        me_response = await client.get("/auth/me", headers=headers)
        assert me_response.status_code == 403  # Forbidden
        
        # Wrong auth type
        headers = {"Authorization": "Basic some-token"}
        me_response = await client.get("/auth/me", headers=headers)
        assert me_response.status_code == 403  # Forbidden

@pytest.mark.asyncio
async def test_login_route_csrf_and_token():
    """Test login returns access token, CSRF token, and sets refresh cookie"""
    email = f"test_{uuid4()}@example.com"
    password = "TestPassword123!"
    
    # Create host first
    host_payload = {
        "email": email,
        "company_name": "Test Company",
        "password": password,
        "created_at": "2023-10-01T12:00:00Z"
    }

    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create host
        host_resp = await client.post("/hosts/", json=host_payload)
        assert host_resp.status_code == 201

        # Login
        login_payload = {"email": email, "password": password, "rememberMe": True}
        login_resp = await client.post("/auth/login", json=login_payload)
        assert login_resp.status_code == 200

        login_data = login_resp.json()
        # Check response contains access token, CSRF token, and user info
        assert "access_token" in login_data
        assert login_data["token_type"] == "bearer"
        assert "csrf_token" in login_data
        assert len(login_data["csrf_token"]) > 0

        # Check that refresh_token cookie is set
        set_cookie = login_resp.headers.get("set-cookie")
        assert "refresh_token=" in set_cookie

        # Check that CSRF token cookie is set (if using cookie for CSRF)
        if "csrf_token=" in set_cookie:
            assert login_data["csrf_token"] in set_cookie

@pytest.mark.asyncio
async def test_complete_auth_flow():
    """Test complete authentication flow: register -> login -> access protected route"""
    email = f"flow_test_{uuid4()}@example.com"
    password = "flowtest123"
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Step 1: Register (create host)
        host_payload = {
            "email": email,
            "company_name": "Flow Test Company",
            "password": password,
            "created_at": "2023-10-01T12:00:00Z"
        }
        
        host_response = await client.post("/hosts/", json=host_payload)
        assert host_response.status_code == 201
        host_data = host_response.json()
        assert host_data["email"] == email
        assert "password_hash" not in host_data  # Should be sanitized
        
        # Step 2: Login
        login_payload = {"email": email, "password": password}
        login_response = await client.post("/auth/login", json=login_payload)
        assert login_response.status_code == 200
        
        login_data = login_response.json()
        token = login_data["access_token"]
        assert login_data["email"] == email
        
        # Step 3: Access protected route (/auth/me)
        headers = {"Authorization": f"Bearer {token}"}
        me_response = await client.get("/auth/me", headers=headers)
        assert me_response.status_code == 200
        
        me_data = me_response.json()
        assert me_data["email"] == email
        assert me_data["host_id"] == host_data["id"]
        
        # Step 6: Clean up
        delete_response = await client.delete(f"/hosts/{host_data['id']}")
        assert delete_response.status_code == 204


@pytest.mark.asyncio
async def test_auth_route_response_schemas():
    """Test that auth routes return data in correct schema format"""
    email = f"schema_test_{uuid4()}@example.com"
    password = "schematest123"
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create host
        host_payload = {
            "email": email,
            "company_name": "Schema Test Company",
            "password": password,
            "created_at": "2023-10-01T12:00:00Z"
        }
        
        host_response = await client.post("/hosts/", json=host_payload)
        host_data = host_response.json()
        
        # Test login response schema
        login_payload = {"email": email, "password": password}
        login_response = await client.post("/auth/login", json=login_payload)
        login_data = login_response.json()
        
        # Verify LoginResponse schema
        required_login_fields = ["access_token", "token_type", "email"]
        for field in required_login_fields:
            assert field in login_data
        
        assert login_data["token_type"] == "bearer"
        assert isinstance(login_data["access_token"], str)
        assert isinstance(login_data["email"], str)
        
        # Test /auth/me response schema
        headers = {"Authorization": f"Bearer {login_data['access_token']}"}
        me_response = await client.get("/auth/me", headers=headers)
        me_data = me_response.json()
        
        # Verify CurrentUserResponse schema
        required_me_fields = ["email", "host_id"]
        for field in required_me_fields:
            assert field in me_data
        
        assert isinstance(me_data["email"], str)
        assert isinstance(me_data["host_id"], str)
        
        # Clean up
        delete_response = await client.delete(f"/hosts/{host_data['id']}")
        assert delete_response.status_code == 204
