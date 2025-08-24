from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    ForeignKey
)
from sqlalchemy.dialects.postgresql import UUID
import uuid
from sqlalchemy.orm import Mapped, mapped_column
from database.session import Base
from sqlalchemy.sql import func
from datetime import datetime

class OTP(Base):
    __tablename__ = "otps"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String, nullable=True)
    label: Mapped[str] = mapped_column(String, nullable=True)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="CASCADE"), nullable=False)
    otp_code: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    used_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    issued_by_host_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
