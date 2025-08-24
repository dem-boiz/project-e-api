from sqlalchemy import (
    Column,
    DateTime,
    func
)
from sqlalchemy.dialects.postgresql import UUID
import uuid
from database.session import Base
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime

class GuestDevice(Base):
    __tablename__ = "guest_devices"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
