import datetime
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
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import uuid
from database.session import Base
from sqlalchemy.sql import func


class Event(Base):
    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_number: Mapped[int] = mapped_column(Integer, Identity(start=1, increment=1), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=True) # We probably want this to not be nullable?
    location: Mapped[str] = mapped_column(String, nullable=False)
    date_time: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    host_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("host_id", "date_time", name="unique_host_per_day"),
    )
