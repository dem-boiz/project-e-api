from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from auth.db_models import OTPRecord
from database.session import SessionLocal
from config.settings import OTP_EXPIRY_SECONDS

def save_otp(email: str, otp: str):
    db: Session = SessionLocal()
    record = OTPRecord(
        email=email,
        otp=otp,
        expires_at=datetime.utcnow() + timedelta(seconds=OTP_EXPIRY_SECONDS)
    )
    db.add(record)
    db.commit()
    db.close()

def get_otp(email: str):
    db: Session = SessionLocal()
    record = db.query(OTPRecord).filter(OTPRecord.email == email).first()
    db.close()
    if record:
        return (record.otp, record.expires_at)
    return None

def delete_otp(email: str):
    db: Session = SessionLocal()
    db.query(OTPRecord).filter(OTPRecord.email == email).delete()
    db.commit()
    db.close()
