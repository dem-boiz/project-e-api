import random
import string
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models.otp import OTP
from models.event import Event
from schema import OTPCreate
from fastapi import HTTPException


def generate_otp_code(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))


def create_otp(db: Session, otp_data: OTPCreate) -> OTP:
    otp_code = generate_otp_code()
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    otp = OTP(
        email=otp_data.email,
        event_id=otp_data.event_id,
        otp_code=otp_code,
        expires_at=expires_at
    )
    db.add(otp)
    db.commit()
    db.refresh(otp)
    return otp


def verify_otp(db: Session, email: str, event_id: str, otp_code: str) -> OTP:
    otp = db.query(OTP).filter(
        OTP.email == email,
        OTP.event_id == event_id,
        OTP.otp_code == otp_code,
        OTP.used == False,
        OTP.expires_at > datetime.utcnow()
    ).first()

    if not otp:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    otp.used = True
    db.commit()
    return otp
