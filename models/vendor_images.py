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
from models import EventVendor
from database.session import Base
from sqlalchemy.sql import func
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime

class VendorImage(Base):
    __tablename__ = "vendor_images"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_vendor_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(EventVendor.__table__.c.id), nullable=False)
    image_data: Mapped[LargeBinary] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())