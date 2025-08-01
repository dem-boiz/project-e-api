from sqlalchemy import (
    Column,
    Boolean,
    DateTime,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from database.session import Base
from sqlalchemy.sql import func


class UserEventAccess(Base):
    __tablename__ = "user_event_access"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
    is_deleted = Column(Boolean, default=False)
    granted_at = Column(DateTime, server_default=func.now())

    # Optional relationships for easier access
