# models/hosting_info.py
from sqlalchemy import Column, String, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime

from database.session import Base

class HostingInfo(Base):
    __tablename__ = "hosting_infos"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    service_name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    vendor_id = Column(UUID(as_uuid=True), ForeignKey("vendors.id"), nullable=False)
    address_id = Column(UUID(as_uuid=True), ForeignKey("addresses.id"), nullable=True)

    vendor = relationship("Vendor", back_populates="hosting_infos")
    address = relationship("Address")
