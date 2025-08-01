import requests

BASE_URL = "http://localhost:8000"
''' test #1 '''
print("\n🔹 Testing /")
res = requests.get(f"{BASE_URL}/")
print("Status Code:", res.status_code)
print("Response:", res.json())


''' test #2 '''
email = "test@example.com"

# Step 1: Request OTP
print("\n🔹 Requesting OTP")
res = requests.post(f"{BASE_URL}/auth/request-otp", json={"email": email})
print("Status Code:", res.status_code)
print("Response:", res.json())

# For testing, you might check your server logs to see the printed OTP
# or temporarily hardcode the OTP you want to test with

# Step 2: Verify OTP with hardcoded OTP (e.g., "123456")
print("\n🔹 Verifying OTP")
verify_payload = {"email": email, "otp": "123456"}
res = requests.post(f"{BASE_URL}/auth/verify-otp", json=verify_payload)

if res.status_code == 200:
    token = res.json().get("token")
    print("Token received:", token)

    # Step 3: Access protected route with token
    print("\n🔹 Testing /me")
    headers = {"Authorization": f"Bearer {token}"}
    res = requests.get(f"{BASE_URL}/me", headers=headers)
    print("Status Code:", res.status_code)
    print("Response:", res.json())
else:
    print("❌ Failed to verify OTP. Status:", res.status_code)
    print("Response:", res.text)