from datetime import datetime
from sqlalchemy import Column, DateTime, ForeignKey, Index, LargeBinary, CheckConstraint
from models import Session
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
from sqlalchemy.orm import Mapped, mapped_column

Base = declarative_base()


class RefreshToken(Base):
    """
    Tracks rotation lineage & reuse detection. **Do not** track access tokens here.
    """
    __tablename__ = 'refresh_tokens'
    
    # Primary key: Refresh token id from JWT. Must be unique.
    jti: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign key: Binds token to its session.
    sid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(Session.__table__.c.sid), nullable=False)

    # User ID: Quick lookup/auditing by user.
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    # Timestamp fields for token lifecycle tracking
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)  # Set when token is **rotated**. If seen again → **reuse/theft**.
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)  # Explicit server revocation (rare, but nice to have).

    # Rotation chain tracking
    parent_jti: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=True)  # Previous refresh token in rotation chain.
    replaced_by_jti: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=True)  # Next token in chain.

    # CSRF protection: Hash of CSRF secret bound to this refresh token (double-submit check).
    csrf_hash: Mapped[str] = mapped_column(LargeBinary, nullable=True)

    # Relationship to session
    #session = relationship("Session", back_populates="refresh_tokens")
    
    # Table-level constraints and indexes
    __table_args__ = (
        # Check constraint for timestamp logic
        CheckConstraint('issued_at <= expires_at', name='chk_refresh_tokens_timestamps'),
        
        # Btree indexes for performance
        Index('idx_refresh_tokens_sid', 'sid'),
        Index('idx_refresh_tokens_user_id', 'user_id'),
        Index('idx_refresh_tokens_expires_at', 'expires_at'),
        
        # Partial index for cleanup job targeting
        Index('idx_refresh_tokens_cleanup', 'expires_at', 
              postgresql_where=(used_at.is_(None) & revoked_at.is_(None))),
        
        # Optional: Unique partial index for "only one live refresh token per session" invariant
        # Index('idx_refresh_tokens_unique_live_per_session', 'sid', unique=True,
        #       postgresql_where=(used_at.is_(None) & revoked_at.is_(None))),
    )

    def __repr__(self):
        return f"<RefreshToken(jti={self.jti}, sid={self.sid}, user_id={self.user_id}, issued_at={self.issued_at})>"

    @property
    def is_expired(self):
        """Check if the refresh token has expired"""
        return datetime.now() > self.expires_at

    @property
    def is_used(self):
        """Check if the refresh token has been used (rotated)"""
        return self.used_at is not None

    @property
    def is_revoked(self):
        """Check if the refresh token has been explicitly revoked"""
        return self.revoked_at is not None

    @property
    def is_valid(self):
        """Check if the refresh token is valid (not expired, used, or revoked)"""
        return not (self.is_expired or self.is_used or self.is_revoked)

    def mark_as_used(self, replaced_by_jti=None):
        """Mark the token as used during rotation"""
        self.used_at = func.now()
        if replaced_by_jti:
            self.replaced_by_jti = replaced_by_jti

    def revoke(self):
        """Explicitly revoke the refresh token"""
        self.revoked_at = func.now()

 