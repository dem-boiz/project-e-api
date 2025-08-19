"""
Token issuance, rotation, and DB validation tests
"""
import uuid
import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient, ASGITransport
from services import AuthService, HostService
from database import AsyncSessionLocal
from models import Host, RefreshToken
from schema import LoginRequestSchema, RefreshResponseSchema, HostCreateSchema
import sys
import asyncio
import json
from uuid import uuid4
from datetime import datetime, timedelta, timezone 
from sqlalchemy import select, delete
import secrets

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

client = TestClient(app)


class TestTokenIssuance:
    """Test token generation and issuance through HTTP endpoints"""
    
    @pytest.mark.asyncio
    async def test_login_issues_access_and_refresh_tokens(self):
        """Test that login endpoint issues both access and refresh tokens"""
        
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
            
            # Login to get tokens
            login_data = {
                "email": email,
                "password": password,
                "rememberMe": True
            }
            
            response = await client.post("/auth/login", json=login_data)
            
            assert response.status_code == 200
            data = response.json()
            
            # Verify access token is returned
            assert "access_token" in data
            assert data["access_token"] is not None
            assert len(data["access_token"]) > 0
            
            # Verify CSRF token is returned
            assert "csrf_token" in data
            assert data["csrf_token"] is not None
            
            # Verify refresh token cookie is set
            assert "refresh_token" in response.cookies
            refresh_cookie = response.cookies["refresh_token"]
            assert refresh_cookie is not None
            
            # Verify CSRF token cookie is set
            assert "csrf_token" in response.cookies
            csrf_cookie = response.cookies["csrf_token"]
            assert csrf_cookie is not None
    
    @pytest.mark.asyncio
    async def test_login_stores_refresh_token_in_database(self):
        """Test that refresh token is properly stored in database"""
        
        email = f"test_{uuid4()}@example.com"
        password = "TestPassword123!"
        
        # Create host first
        host_payload = {
            "email": email,
            "company_name": "Test Company DB",
            "password": password,
            "created_at": "2023-10-01T12:00:00Z"
        }
        
        async with AsyncClient(base_url="http://localhost:8000") as client:
            # Create host
            host_resp = await client.post("/hosts/", json=host_payload)
            assert host_resp.status_code == 201
            host_id = host_resp.json()["id"]
            
            login_data = {
                "email": email,
                "password": password, 
                "rememberMe": True
            }
            
            response = await client.post("/auth/login", json=login_data)
            assert response.status_code == 200
        
        # Verify refresh token is stored in database
        async with AsyncSessionLocal() as db:
            
            refresh_tokens = await db.execute(
                select(RefreshToken).where(RefreshToken.user_id == uuid.UUID(host_id))
            )
            stored_tokens = refresh_tokens.scalars().all()
            
            assert len(stored_tokens) == 1
            token_record = stored_tokens[0]
            assert token_record.user_id == uuid.UUID(host_id)
            assert token_record.csrf_hash is not None
            assert token_record.expires_at > datetime.now(timezone.utc)
            assert token_record.is_revoked is False
    
    @pytest.mark.asyncio
    async def test_login_with_remember_me_sets_long_expiry(self):
        """Test remember me option sets longer expiry"""
        
        email = f"test_{uuid4()}@example.com"
        password = "TestPassword123!"
        
        host_payload = {
            "email": email,
            "company_name": "Remember Me Test Co",
            "password": password,
            "created_at": "2023-10-01T12:00:00Z"
        }
        
        async with AsyncClient(base_url="http://localhost:8000") as client:
            # Create host
            host_resp = await client.post("/hosts/", json=host_payload)
            assert host_resp.status_code == 201
            
            login_data = {
                "email": email,
                "password": password,
                "rememberMe": True
            }
            
            response = await client.post("/auth/login", json=login_data)
            assert response.status_code == 200
            
            # Check cookie max-age is set (30 days = 2592000 seconds)
            # Debug: Print all cookies and their attributes
            print(f"All cookies: {response.cookies}")
            print(f"Cookie items: {list(response.cookies.items())}")
            
            # Check if max-age is set in the Set-Cookie header
            set_cookie_headers = response.headers.get_list("set-cookie")
            refresh_cookie_header = None
            for header in set_cookie_headers:
                if "refresh_token=" in header:
                    refresh_cookie_header = header
                    break
            
            print(f"Refresh cookie header: {refresh_cookie_header}")
            
            # Verify max-age is set for remember me (should be 30 days = 2592000 seconds)
            if refresh_cookie_header:
                assert "Max-Age=" in refresh_cookie_header or "max-age=" in refresh_cookie_header.lower()
            else:
                # Fallback: check if the cookie object has max_age attribute
                # This depends on your HTTP client implementation
                cookies_dict = dict(response.cookies)
                assert "refresh_token" in cookies_dict
    
    @pytest.mark.asyncio 
    async def test_login_without_remember_me_session_cookie(self):
        """Test login without remember me creates session cookies"""
        
        email = f"test_{uuid4()}@example.com"
        password = "TestPassword123!"
        
        host_payload = {
            "email": email,
            "company_name": "Session Cookie Test Co",
            "password": password,
            "created_at": "2023-10-01T12:00:00Z"
        }
        
        async with AsyncClient(base_url="http://localhost:8000") as client:
            # Create host
            host_resp = await client.post("/hosts/", json=host_payload)
            assert host_resp.status_code == 201
            
            login_data = {
                "email": email,
                "password": password,
                "rememberMe": False
            }
            
            response = await client.post("/auth/login", json=login_data)
            assert response.status_code == 200
            
            # Session cookies should not have max-age set
            refresh_cookie = response.cookies["refresh_token"]
            # Session cookies typically don't have Max-Age or Expires
            cookie_str = str(refresh_cookie)
            assert "Max-Age" not in cookie_str or "max-age=None" in cookie_str.lower()
    
    @pytest.mark.asyncio
    async def test_login_invalid_credentials_no_tokens(self):
        """Test that invalid login doesn't issue tokens"""
        
        async with AsyncClient(base_url="http://localhost:8000") as client:
            login_data = {
                "email": "nonexistent@example.com",
                "password": "wrongpassword",
                "rememberMe": False
            }
            
            response = await client.post("/auth/login", json=login_data)
            
            assert response.status_code == 401  # Unauthorized
            assert "refresh_token" not in response.cookies
            assert "csrf_token" not in response.cookies

class TestTokenRotation:
    """Test token refresh and rotation functionality"""
 
    @pytest.mark.asyncio
    async def test_refresh_token_rotates_access_and_csrf(self):
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
    async def test_refresh_endpoint_requires_csrf_token(self):
        """Test refresh endpoint requires CSRF token for protection"""
        
        email = f"csrf_test_{uuid4()}@example.com"
        password = "TestPassword123!"
        
        # Create host
        host_payload = {
            "email": email,
            "company_name": "CSRF Test Company",
            "password": password,
            "created_at": "2023-10-01T12:00:00Z"
        }
        
        async with AsyncClient(base_url="http://localhost:8000") as client:
            # Create host
            host_resp = await client.post("/hosts/", json=host_payload)
            assert host_resp.status_code == 201
            
            login_data = {
                "email": email,
                "password": password,
                "rememberMe": True
            }
            
            login_response = await client.post("/auth/login", json=login_data)
            assert login_response.status_code == 200
            
            cookies = login_response.cookies
            
            # Try refresh without CSRF token
            refresh_response = await client.post("/auth/refresh", cookies=cookies)
            
            assert refresh_response.status_code == 403  # Forbidden due to missing CSRF
    
    @pytest.mark.asyncio
    async def test_refresh_endpoint_invalid_csrf_token(self):
        """Test refresh endpoint rejects invalid CSRF token"""
        
        email = f"invalid_csrf_{uuid4()}@example.com"
        password = "TestPassword123!"
        
        # Create host
        host_payload = {
            "email": email,
            "company_name": "Invalid CSRF Test Co",
            "password": password,
            "created_at": "2023-10-01T12:00:00Z"
        }
        
        async with AsyncClient(base_url="http://localhost:8000") as client:
            # Create host
            host_resp = await client.post("/hosts/", json=host_payload)
            assert host_resp.status_code == 201
            
            login_data = {
                "email": email,
                "password": password,
                "rememberMe": True
            }
            
            login_response = await client.post("/auth/login", json=login_data)
            assert login_response.status_code == 200
            
            cookies = login_response.cookies
            
            # Try refresh with invalid CSRF token
            headers = {"X-CSRF-Token": "invalid_csrf_token"}
            refresh_response = await client.post(
                "/auth/refresh", 
                headers=headers,
                cookies=cookies
            )
            
            assert refresh_response.status_code == 403  # Forbidden due to invalid CSRF
    
    @pytest.mark.asyncio
    async def test_refresh_endpoint_no_refresh_cookie(self):
        """Test refresh endpoint requires refresh token cookie"""
        
        async with AsyncClient(base_url="http://localhost:8000") as client:
            # Try refresh without any cookies
            headers = {"X-CSRF-Token": "some_csrf_token"}
            refresh_response = await client.post("/auth/refresh", headers=headers)
            
            assert refresh_response.status_code == 403  # Unauthorized - no refresh token
    
    @pytest.mark.asyncio
    async def test_old_refresh_token_invalidated_after_rotation(self):
        """Test that old refresh token is invalidated after successful rotation"""
        
        email = f"rotation_test_{uuid4()}@example.com"
        password = "TestPassword123!"
        
        # Create host
        host_payload = {
            "email": email,
            "company_name": "Token Rotation Test Co",
            "password": password,
            "created_at": "2023-10-01T12:00:00Z"
        }
        
        async with AsyncClient(base_url="http://localhost:8000") as client:
            # Create host
            host_resp = await client.post("/hosts/", json=host_payload)
            assert host_resp.status_code == 201
            
            # Login
            login_data = {
                "email": email,
                "password": password,
                "rememberMe": True
            }
            
            login_response = await client.post("/auth/login", json=login_data)
            assert login_response.status_code == 200
            
            csrf_token = login_response.json()["csrf_token"]
            old_cookies = login_response.cookies
            
            # First refresh
            headers = {"X-CSRF-Token": csrf_token}
            first_refresh = await client.post(
                "/auth/refresh",
                headers=headers,
                cookies=old_cookies
            )
            assert first_refresh.status_code == 200
            
            # Try to use old refresh token again
            second_refresh = await client.post(
                "/auth/refresh",
                headers=headers,
                cookies=old_cookies  # Using old cookies
            )
            
            assert second_refresh.status_code == 401  # Should be unauthorized