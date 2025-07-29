import requests

url = "http://127.0.0.1:8000/auth/request-otp"

data = {
    "email": "test@example.com"
}

response = requests.post(url, json=data)

print("Status Code:", response.status_code)
print("Response:", response.json())
