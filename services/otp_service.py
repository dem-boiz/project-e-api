import random
import string
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models.otp import OTP
from models.event import Event
from schema import OTPCreate
from fastapi import HTTPException

class OTPService:
    def __init__(self, db: Session):
        self.db = db

    async def generate_otp(self, otp_data: OTPCreate) -> OTP:
        otp_code = self.generate_otp_code()
        expires_at = datetime.utcnow() + timedelta(minutes=10)

        otp = OTP(
            email=otp_data.email,
            event_id=otp_data.event_id,
            otp_code=otp_code,
            expires_at=expires_at
        )
        self.db.add(otp)
        self.db.commit()
        self.db.refresh(otp)
        return otp

    async def verify_otp(self, email: str, event_id: str, otp_code: str) -> bool:
        otp = self.db.query(OTP).filter(
            OTP.email == email,
            OTP.event_id == event_id,
            OTP.otp_code == otp_code,
            OTP.used == False,
            OTP.expires_at > datetime.utcnow()
        ).first()

        if not otp:
            raise HTTPException(status_code=400, detail="Invalid or expired OTP")

        otp.used = True
        self.db.commit()
        return True