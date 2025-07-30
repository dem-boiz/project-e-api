# models/address.py
from sqlalchemy import Column, String
from sqlalchemy.dialects.postgresql import UUID
import uuid

from database.session import Base

class Address(Base):
    __tablename__ = "addresses"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    street = Column(String, nullable=False)
    city = Column(String, nullable=False)
    state = Column(String)
    country = Column(String, nullable=False)
    zip_code = Column(String)
