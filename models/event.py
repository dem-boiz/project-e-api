from sqlalchemy import (
    Column,
    String,
    DateTime,
    Date,
    Integer,
    ForeignKey,
    UniqueConstraint,
    Computed
)
from sqlalchemy.dialects.postgresql import UUID
import uuid
from database.session import Base
from sqlalchemy.sql import func


class Event(Base):
    __tablename__ = "events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_number = Column(Integer, unique=True, autoincrement=True)
    event_name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    location = Column(String, nullable=False)
    event_datetime = Column(DateTime, nullable=False)
    event_date = Column(Date, Computed("event_datetime::date", persisted=True))
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("host_id", "event_date", name="unique_host_per_day"),
    )
