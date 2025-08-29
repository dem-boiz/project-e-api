from sqlalchemy import (
    DateTime,
    ForeignKey,
    Text,
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
    invite_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("invites.id", ondelete="SET NULL"), nullable=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    granted_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    type: Mapped[str] = mapped_column(Text, nullable=True)
    # Optional relationships for easier access
