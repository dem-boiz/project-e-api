from datetime import datetime, timedelta
from config.settings import OTP_EXPIRY_SECONDS

# In-memory OTP store (email -> (otp, expiry))
otp_store = {}

def save_otp(email: str, otp: str):
    expiry = datetime.utcnow() + timedelta(seconds=OTP_EXPIRY_SECONDS)
    otp_store[email] = (otp, expiry)

def get_otp(email: str):
    return otp_store.get(email)

def delete_otp(email: str):
    if email in otp_store:
        del otp_store[email]
