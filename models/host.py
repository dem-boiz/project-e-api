from sqlalchemy import Column, String, DateTime, Integer, UniqueConstraint, Identity
from sqlalchemy.dialects.postgresql import UUID
import uuid
from database.session import Base
from sqlalchemy.sql import func

class Host(Base):
    __tablename__ = "hosts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_number = Column(Integer, Identity(start=1, increment=1), unique=True, nullable=False)
    company_name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
