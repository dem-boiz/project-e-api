from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Text, Index
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from models import Host
import uuid
from sqlalchemy.schema import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
Base = declarative_base()


class Session(Base):
    """
    Tracks each device/login session.
    Powers instant logout and global/account logout functionality.
    """
    __tablename__ = 'sessions'
    
    # Primary key: unique session identifier embedded in JWT
    sid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # TODO: Should Host be used or User? 
    # Foreign key to users table
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(Host.__table__.c.id), nullable=False)

    # Timestamp fields for session lifecycle tracking
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    # Instant logout flag: if set, any token with iat <= revoked_at is invalid
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # Optional fields for security and analytics
    user_agent: Mapped[str] = mapped_column(Text, nullable=True)
    ip: Mapped[str] = mapped_column(INET, nullable=True)

    # Relationships
    #user = relationship("User") 
    #user = relationship("User", back_populates="sessions")
    #refresh_tokens = relationship("RefreshToken", back_populates="session", cascade="all, delete-orphan")
    
    # Table-level indexes
    __table_args__ = (
        # Btree index on user_id for efficient user session lookups
        Index('idx_sessions_user_id', 'user_id'),
        # Partial index for active sessions (where revoked_at IS NULL)
        Index('idx_sessions_active', 'user_id', postgresql_where=(revoked_at.is_(None))),
    )

    def __repr__(self):
        return f"<Session(sid={self.sid}, user_id={self.user_id}, created_at={self.created_at})>"

    @property
    def is_active(self) -> bool:
        """Check if session is active (not revoked)"""
        return self.revoked_at is None

    def revoke(self):
        """Revoke the session (instant logout)"""
        self.revoked_at = func.now()

    def update_last_seen(self):
        """Update last_seen_at timestamp"""
        self.last_seen_at = func.now()