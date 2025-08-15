from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class RefreshTokenBase(BaseModel):
    """Base refresh token model with common fields"""
    user_id: UUID = Field(..., description="User ID for quick lookup and auditing")
    expires_at: datetime = Field(..., description="Refresh token TTL - cleanup job target")
    parent_jti: Optional[UUID] = Field(None, description="Previous refresh token in rotation chain")
    replaced_by_jti: Optional[UUID] = Field(None, description="Next token in rotation chain")


class RefreshTokenCreate(RefreshTokenBase):
    """Model for creating a new refresh token"""
    sid: UUID = Field(..., description="Session ID - binds token to its session")
    csrf_hash: Optional[bytes] = Field(None, description="Hash of CSRF secret for double-submit protection")
    
    model_config = ConfigDict(
        json_encoders={
            bytes: lambda v: v.hex() if v else None
        }
    )


class RefreshTokenUpdate(BaseModel):
    """Model for updating a refresh token (mainly for rotation)"""
    used_at: Optional[datetime] = Field(None, description="Set when token is rotated")
    revoked_at: Optional[datetime] = Field(None, description="Explicit server revocation timestamp")
    replaced_by_jti: Optional[UUID] = Field(None, description="Next token in rotation chain")


class RefreshToken(RefreshTokenBase):
    """Complete refresh token model for responses"""
    jti: UUID = Field(..., description="Refresh token ID from JWT - must be unique")
    sid: UUID = Field(..., description="Session ID - binds token to its session")
    issued_at: datetime = Field(..., description="Token issuance timestamp")
    used_at: Optional[datetime] = Field(None, description="Set when token is rotated - if seen again indicates reuse/theft")
    revoked_at: Optional[datetime] = Field(None, description="Explicit server revocation timestamp")
    csrf_hash: Optional[bytes] = Field(None, description="Hash of CSRF secret for double-submit protection")

    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={
            bytes: lambda v: v.hex() if v else None
        }
    )

    @property
    def is_expired(self) -> bool:
        """Check if the refresh token has expired"""
        return datetime.utcnow() > self.expires_at

    @property
    def is_used(self) -> bool:
        """Check if the refresh token has been used (rotated)"""
        return self.used_at is not None

    @property
    def is_revoked(self) -> bool:
        """Check if the refresh token has been explicitly revoked"""
        return self.revoked_at is not None

    @property
    def is_valid(self) -> bool:
        """Check if the refresh token is valid (not expired, used, or revoked)"""
        return not (self.is_expired or self.is_used or self.is_revoked)


class RefreshTokenInDB(RefreshToken):
    """Database representation of refresh token (includes all fields)"""
    pass


class RefreshTokenRotation(BaseModel):
    """Model for token rotation operations"""
    old_jti: UUID = Field(..., description="JTI of token being rotated")
    new_jti: UUID = Field(..., description="JTI of new token")
    new_expires_at: datetime = Field(..., description="Expiration of new token")
    csrf_hash: Optional[bytes] = Field(None, description="CSRF hash for new token")

    model_config = ConfigDict(
        json_encoders={
            bytes: lambda v: v.hex() if v else None
        }
    )


class RefreshTokenValidation(BaseModel):
    """Model for token validation responses"""
    jti: UUID
    is_valid: bool
    is_expired: bool
    is_used: bool
    is_revoked: bool
    user_id: UUID
    sid: UUID
    reuse_detected: bool = Field(False, description="True if token reuse was detected")

    
class RefreshTokenCleanup(BaseModel):
    """Model for cleanup job responses"""
    deleted_count: int = Field(..., description="Number of expired tokens deleted")
    oldest_deleted: Optional[datetime] = Field(None, description="Timestamp of oldest deleted token")
    cleanup_timestamp: datetime = Field(default_factory=datetime.utcnow, description="When cleanup was performed")


class RefreshTokenStats(BaseModel):
    """Model for refresh token statistics"""
    total_tokens: int = Field(..., description="Total number of refresh tokens")
    active_tokens: int = Field(..., description="Number of active (valid) tokens")
    expired_tokens: int = Field(..., description="Number of expired tokens")
    used_tokens: int = Field(..., description="Number of used/rotated tokens")
    revoked_tokens: int = Field(..., description="Number of explicitly revoked tokens")
    user_id: Optional[UUID] = Field(None, description="User ID if stats are per-user")
    sid: Optional[UUID] = Field(None, description="Session ID if stats are per-session")


# API Request/Response models
class TokenRotateRequest(BaseModel):
    """Request model for token rotation endpoint"""
    refresh_token: str = Field(..., description="Current refresh token JWT")
    csrf_token: Optional[str] = Field(None, description="CSRF token for double-submit protection")


class TokenRotateResponse(BaseModel):
    """Response model for token rotation endpoint"""
    access_token: str = Field(..., description="New access token")
    refresh_token: str = Field(..., description="New refresh token")
    expires_in: int = Field(..., description="Access token expiration in seconds")
    token_type: str = Field(default="Bearer", description="Token type")


class TokenRevokeRequest(BaseModel):
    """Request model for token revocation"""
    refresh_token: Optional[str] = Field(None, description="Specific token to revoke")
    revoke_all_user_tokens: bool = Field(False, description="Revoke all tokens for user")
    revoke_all_session_tokens: bool = Field(False, description="Revoke all tokens for session")


class TokenRevokeResponse(BaseModel):
    """Response model for token revocation"""
    revoked_count: int = Field(..., description="Number of tokens revoked")
    message: str = Field(..., description="Success message")


# Error models
class RefreshTokenError(BaseModel):
    """Base error model for refresh token operations"""
    error: str = Field(..., description="Error type")
    description: str = Field(..., description="Error description")
    jti: Optional[UUID] = Field(None, description="Token JTI if relevant")


class TokenReuseError(RefreshTokenError):
    """Specific error for token reuse detection"""
    error: str = Field(default="token_reuse", description="Token reuse detected")
    description: str = Field(default="Refresh token has already been used", description="Error description")
    detected_at: datetime = Field(default_factory=datetime.utcnow, description="When reuse was detected")
    original_use_at: Optional[datetime] = Field(None, description="When token was originally used")


class TokenExpiredError(RefreshTokenError):
    """Specific error for expired tokens"""
    error: str = Field(default="token_expired", description="Token expired")
    description: str = Field(default="Refresh token has expired", description="Error description")
    expired_at: datetime = Field(..., description="When token expired")


class TokenRevokedError(RefreshTokenError):
    """Specific error for revoked tokens"""
    error: str = Field(default="token_revoked", description="Token revoked")
    description: str = Field(default="Refresh token has been revoked", description="Error description")
    revoked_at: datetime = Field(..., description="When token was revoked")