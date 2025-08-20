from sqlalchemy import (
    Column,
    String,
    DateTime,
    ForeignKey
)
from sqlalchemy.dialects.postgresql import UUID
import uuid
from database.session import Base


class DeviceGrant(Base):
    __tablename__ = "device_grants"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("guest_devices.id", ondelete="CASCADE"), nullable=False)
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String, unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    issued_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    created_from_otp_id = Column(UUID(as_uuid=True), ForeignKey("otps.id", ondelete="SET NULL"), nullable=True)