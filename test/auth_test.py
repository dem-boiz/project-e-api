import requests

BASE_URL = "http://127.0.0.1:8000"

# 1. Test /auth/request-otp
print("🔹 Testing /auth/request-otp")
request_otp_url = f"{BASE_URL}/auth/request-otp"
email = "test@example.com"

response = requests.post(request_otp_url, json={"email": email})
print("Status Code:", response.status_code)
print("Response:", response.json())

# Ask user to manually check OTP from logs (since OTP is printed to console)
otp = input("Enter OTP from logs: ")

# 2. Test /auth/verify-otp
print("\n🔹 Testing /auth/verify-otp")
verify_otp_url = f"{BASE_URL}/auth/verify-otp"
response = requests.post(verify_otp_url, json={"email": email, "otp": otp})

print("Status Code:", response.status_code)
print("Response:", response.json())

if response.status_code == 200:
    token = response.json()["token"]
else:
    print("❌ OTP verification failed.")
    exit(1)
