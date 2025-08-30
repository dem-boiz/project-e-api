from typing import List, Optional
from sqlalchemy import (
    ARRAY,
    DateTime,
    ForeignKey,
    LargeBinary,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from models import Event, User
from database.session import Base
from sqlalchemy.sql import func
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime

class EventVendor(Base):
    __tablename__ = "event_vendors"

    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(Event.__table__.c.id), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(User.__table__.c.id), primary_key=True)
    event_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    vendor_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True, server_default=None)
    vendor_images: Mapped[Optional[List[bytes]]] = mapped_column(ARRAY(LargeBinary), nullable=True, server_default=None)
    added_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
 