from fastapi import APIRouter, HTTPException
from .models import OTPRequest, OTPVerify, TokenResponse
from .utils import generate_otp, create_jwt, verify_jwt
from .store import save_otp, get_otp, delete_otp

router = APIRouter(prefix="/auth")

@router.post("/request-otp")
def request_otp(data: OTPRequest):
    otp = generate_otp()
    save_otp(data.email, otp)
    print(f"OTP for {data.email}: {otp}")
    return {"message": "OTP sent (check logs in this demo)"}

@router.post("/verify-otp", response_model=TokenResponse)
def verify_otp(data: OTPVerify):
    record = get_otp(data.email)
    if not record:
        raise HTTPException(400, "OTP not requested")
    otp, expiry = record
    from datetime import datetime
    if datetime.utcnow() > expiry:
        raise HTTPException(400, "OTP expired")
    if data.otp != otp:
        raise HTTPException(401, "Invalid OTP")
    
    token = create_jwt(data.email)
    delete_otp(data.email)
    return {"token": token}
