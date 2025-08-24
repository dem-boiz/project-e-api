from sqlalchemy import (
    Column,
    String,
    DateTime,
    ForeignKey
)
from sqlalchemy.dialects.postgresql import UUID
import uuid
from database.session import Base
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime



class DeviceGrant(Base):
    __tablename__ = "device_grants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("guest_devices.id", ondelete="CASCADE"), nullable=False)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_from_otp_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("otps.id", ondelete="SET NULL"), nullable=True)