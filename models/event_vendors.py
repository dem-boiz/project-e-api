from sqlalchemy import (
    Column,
    Date,
    DateTime,
    ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from database.session import Base
from sqlalchemy.sql import func


class EventVendor(Base):
    __tablename__ = "event_vendors"

    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
    vendor_id = Column(UUID(as_uuid=True), ForeignKey("vendors.id", ondelete="CASCADE"), primary_key=True)
    event_date = Column(Date, nullable=False)
    added_at = Column(DateTime, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("vendor_id", "event_date", name="unique_vendor_per_day"),
    )

    # Optional relationships for easier access
    event = relationship("Event", backref="vendors")
    vendor = relationship("Vendor", backref="events")
