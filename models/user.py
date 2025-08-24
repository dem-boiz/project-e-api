from sqlalchemy import Column, String, DateTime, Boolean, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
import uuid
from database.session import Base
from sqlalchemy.sql import func
from typing import TYPE_CHECKING
from datetime import datetime


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text('false'))

    # Use string reference instead of class reference
    #sessions = relationship("Session", back_populates="users", cascade="all, delete-orphan")