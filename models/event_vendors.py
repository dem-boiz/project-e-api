from sqlalchemy import (
    DateTime,
    ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from database.session import Base
from sqlalchemy.sql import func
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime

class EventVendor(Base):
    __tablename__ = "event_vendors"

    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
    vendor_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("vendors.id", ondelete="CASCADE"), primary_key=True)
    event_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("vendor_id", "event_date", name="unique_vendor_per_day"),
    )

    # Optional relationships for easier access
    event = relationship("Event", backref="vendors")
    vendor = relationship("Vendor", backref="events")
