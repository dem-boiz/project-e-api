from sqlalchemy import (
    Column,
    Boolean,
    DateTime,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from sqlalchemy.orm import Mapped, mapped_column
from database.session import Base
from sqlalchemy.sql import func
from datetime import datetime


class UserEventAccess(Base):
    __tablename__ = "user_event_access"

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
    otp_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("otps.id", ondelete="SET NULL"), nullable=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    # Optional relationships for easier access
