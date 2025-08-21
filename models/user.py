from sqlalchemy import Column, String, DateTime, Boolean, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from database.session import Base
from sqlalchemy.sql import func
from typing import TYPE_CHECKING

# Only import Session for type checking, not at runtime
if TYPE_CHECKING:
    from models.sessions import Session

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    is_deleted = Column(Boolean, nullable=False, server_default=text('false'))
    
    # Use string reference instead of class reference
    #sessions = relationship("Session", back_populates="users", cascade="all, delete-orphan")