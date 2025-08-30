from sqlalchemy import JSON, Column, Identity, Integer, String, DateTime, Boolean, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
import uuid
from database.session import Base
from sqlalchemy.sql import func
from typing import TYPE_CHECKING, Optional
from datetime import datetime


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_number: Mapped[int] = mapped_column(Integer, Identity(start=1, increment=1), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False) 
    name: Mapped[str] = mapped_column(Text, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    contact_info: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text('false'))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text('true')) 
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    
    # Use string reference instead of class reference
    #sessions = relationship("Session", back_populates="users", cascade="all, delete-orphan")