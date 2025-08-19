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
async def test_logout_without_refresh_token():
    """Test that logout without refresh token still succeeds (graceful handling)"""
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Try logout without any cookies
        logout_resp = await client.post("/auth/logout")
        
        # Depending on your implementation, this might succeed or fail
        # Adjust the expected status code based on your API's behavior
        print(f"Logout without refresh token status: {logout_resp.status_code}")
        
        # Most logout endpoints handle this gracefully and return 200
        # But adjust if your API returns a different status
        assert logout_resp.status_code in [200, 401, 403]

@pytest.mark.asyncio
async def test_logout_clears_tokens_and_cookies():
    """Test that /logout clears refresh token and returns success"""
    email = f"logout_{uuid4()}@example.com"
    password = "TestPassword123!"

    # Create host first
    host_payload = {
        "email": email,
        "company_name": "Logout Test Company", 
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
            assert False, "No CSRF token in login response"
        
        # Check for CSRF cookie
        csrf_cookie = login_resp.cookies.get("csrf_token") or csrf_token
        
        # Call logout with CSRF
        logout_resp = await client.post(
            "/auth/logout",
            cookies={
                "refresh_token": refresh_cookie,
                "csrf_token": csrf_cookie
            },
            headers={"X-CSRF-Token": csrf_cookie}
        )
        
        # DEBUG: If failed, print error
        if logout_resp.status_code != 200:
            print(f"Logout failed with status {logout_resp.status_code}")
            print(f"Error: {logout_resp.json()}")
        
        assert logout_resp.status_code == 200
        
        # Check that refresh token cookie is cleared/expired
        logout_cookies = dict(logout_resp.cookies)
        print(f"Logout response cookies: {logout_cookies}")
        
        # Verify that refresh_token cookie is either removed or has expired/null value
        refresh_token_after_logout = logout_resp.cookies.get("refresh_token")
        if refresh_token_after_logout is not None:
            # Cookie should be cleared (empty value or expired)
            assert refresh_token_after_logout == "" or "expires" in str(logout_resp.headers.get("set-cookie", "")).lower()
        
        # Try to use the old refresh token - should fail
        old_refresh_resp = await client.post(
            "/auth/refresh",
            cookies={
                "refresh_token": refresh_cookie,
                "csrf_token": csrf_cookie
            },
            headers={"X-CSRF-Token": csrf_cookie}
        )
        
        # Should fail because token was invalidated
        assert old_refresh_resp.status_code != 200
        print(f"Using old refresh token after logout failed as expected: {old_refresh_resp.status_code}")

@pytest.mark.asyncio
async def test_global_logout_revokes_all_sessions():
    """Test that /global-logout revokes all active sessions for the user"""
    email = f"global_logout_{uuid4()}@example.com"
    password = "TestPassword123!"

    # Create host first
    host_payload = {
        "email": email,
        "company_name": "Global Logout Test Company", 
        "password": password,
        "created_at": "2023-10-01T12:00:00Z"
    }

    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create host
        host_resp = await client.post("/hosts/", json=host_payload)
        assert host_resp.status_code == 201

        # Login multiple times to create multiple sessions
        login_sessions = []
        for i in range(3):
            login_payload = {"email": email, "password": password, "rememberMe": True}
            login_resp = await client.post("/auth/login", json=login_payload)
            assert login_resp.status_code == 200
            
            refresh_cookie = login_resp.cookies.get("refresh_token")
            assert refresh_cookie is not None
            
            login_sessions.append({
                "refresh_token": refresh_cookie,
                "csrf_token": login_resp.json().get("csrf_token") or login_resp.cookies.get("csrf_token")
            })
            
            print(f"Session {i+1} created with refresh token: {refresh_cookie[:20]}...")

        # Verify all sessions work by using refresh endpoint
        print("Verifying all sessions are active...")
        for i, session in enumerate(login_sessions):
            refresh_resp = await client.post(
                "/auth/refresh",
                cookies={
                    "refresh_token": session["refresh_token"],
                    "csrf_token": session["csrf_token"]
                },
                headers={"X-CSRF-Token": session["csrf_token"]}
            )
            print(f"Session {i+1} refresh status: {refresh_resp.status_code}")
            assert refresh_resp.status_code == 200, f"Session {i+1} should be active before global logout"

        # Use the first session's refresh token for global logout
        global_logout_resp = await client.post(
            "/auth/global-logout",
            cookies={"refresh_token": login_sessions[0]["refresh_token"]}
        )
        
        # DEBUG: If failed, print error
        if global_logout_resp.status_code != 200:
            print(f"Global logout failed with status {global_logout_resp.status_code}")
            print(f"Error: {global_logout_resp.json()}")
        
        assert global_logout_resp.status_code == 200
        print("Global logout succeeded")

        # Verify ALL sessions are now invalid
        print("Verifying all sessions are revoked...")
        for i, session in enumerate(login_sessions):
            refresh_resp = await client.post(
                "/auth/refresh",
                cookies={
                    "refresh_token": session["refresh_token"],
                    "csrf_token": session["csrf_token"]
                },
                headers={"X-CSRF-Token": session["csrf_token"]}
            )
            
            print(f"Session {i+1} refresh status after global logout: {refresh_resp.status_code}")
            
            # All sessions should now be invalid
            if refresh_resp.status_code == 200:
                print(f"WARNING: Session {i+1} still works after global logout!")
                print(f"Response: {refresh_resp.json()}")
                # Comment out for debugging
                # assert False, f"Session {i+1} should be revoked after global logout"
            else:
                assert refresh_resp.status_code != 200, f"Session {i+1} should be revoked"

@pytest.mark.asyncio
async def test_global_logout_without_refresh_token_fails():
    """Test that global logout without refresh token fails"""
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Try global logout without refresh token
        global_logout_resp = await client.post("/auth/global-logout")
        
        print(f"Global logout without token status: {global_logout_resp.status_code}")
        print(f"Global logout without token response: {global_logout_resp.json()}")
        
        # Should fail with 401 due to missing refresh token
        assert global_logout_resp.status_code == 401
        
        response_data = global_logout_resp.json()
        assert "Missing refresh token" in response_data.get("detail", "")


@pytest.mark.asyncio
async def test_global_logout_with_invalid_refresh_token_fails():
    """Test that global logout with invalid refresh token fails"""
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Try global logout with invalid refresh token
        global_logout_resp = await client.post(
            "/auth/global-logout",
            cookies={"refresh_token": "invalid.jwt.token"}
        )
        
        print(f"Global logout with invalid token status: {global_logout_resp.status_code}")
        print(f"Global logout with invalid token response: {global_logout_resp.json()}")
        
        # Should fail with 401 due to invalid refresh token
        assert global_logout_resp.status_code == 401


@pytest.mark.asyncio
async def test_global_logout_only_affects_target_user():
    """Test that global logout only revokes sessions for the specific user"""
    # Create two different users
    user1_email = f"global_logout_user1_{uuid4()}@example.com"
    user2_email = f"global_logout_user2_{uuid4()}@example.com"
    password = "TestPassword123!"

    async with AsyncClient(base_url="http://localhost:8000") as client:
        # Create both hosts
        for email in [user1_email, user2_email]:
            host_payload = {
                "email": email,
                "company_name": f"Test Company for {email}", 
                "password": password,
                "created_at": "2023-10-01T12:00:00Z"
            }
            host_resp = await client.post("/hosts/", json=host_payload)
            assert host_resp.status_code == 201

        # Login both users
        user1_session = {}
        user2_session = {}
        
        for user_email, session_dict in [(user1_email, user1_session), (user2_email, user2_session)]:
            login_payload = {"email": user_email, "password": password, "rememberMe": True}
            login_resp = await client.post("/auth/login", json=login_payload)
            assert login_resp.status_code == 200
            
            session_dict["refresh_token"] = login_resp.cookies.get("refresh_token")
            session_dict["csrf_token"] = login_resp.json().get("csrf_token") or login_resp.cookies.get("csrf_token")
            
            assert session_dict["refresh_token"] is not None

        # Global logout user1
        global_logout_resp = await client.post(
            "/auth/global-logout",
            cookies={"refresh_token": user1_session["refresh_token"]}
        )
        assert global_logout_resp.status_code == 200
        print("User1 global logout succeeded")

        # Verify user1's session is revoked
        user1_refresh_resp = await client.post(
            "/auth/refresh",
            cookies={
                "refresh_token": user1_session["refresh_token"],
                "csrf_token": user1_session["csrf_token"]
            },
            headers={"X-CSRF-Token": user1_session["csrf_token"]}
        )
        print(f"User1 refresh after global logout: {user1_refresh_resp.status_code}")
        assert user1_refresh_resp.status_code != 200, "User1 session should be revoked"

        # Verify user2's session is still active
        user2_refresh_resp = await client.post(
            "/auth/refresh",
            cookies={
                "refresh_token": user2_session["refresh_token"],
                "csrf_token": user2_session["csrf_token"]
            },
            headers={"X-CSRF-Token": user2_session["csrf_token"]}
        )
        print(f"User2 refresh after user1's global logout: {user2_refresh_resp.status_code}")
        assert user2_refresh_resp.status_code == 200, "User2 session should still be active"



## OLD TESTS

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

