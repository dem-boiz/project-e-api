from sqlalchemy import (
    Column,
    String,
    DateTime,
    Date,
    Integer,
    ForeignKey,
    UniqueConstraint,
    Computed,
    Identity
)
from sqlalchemy.dialects.postgresql import UUID
import uuid
from database.session import Base
from sqlalchemy.sql import func


class Event(Base):
    __tablename__ = "events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_number = Column(Integer, Identity(start=1, increment=1), unique=True, nullable=False)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True) # We probably want this to not be nullable?
    location = Column(String, nullable=False)
    date_time = Column(DateTime(timezone=True), nullable=False)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("host_id", "date_time", name="unique_host_per_day"),
    )
