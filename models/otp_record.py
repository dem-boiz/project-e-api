from sqlalchemy import Column, String, DateTime
from database.session import Base
import uuid
from datetime import datetime, timedelta

class OTPRecord(Base):
    __tablename__ = "otp_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, index=True)
    otp = Column(String)
    expires_at = Column(DateTime)

    def is_expired(self):
        return datetime.utcnow() > self.expires_at
