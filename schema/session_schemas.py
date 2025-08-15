from datetime import datetime
from typing import Optional
from uuid import UUID
import uuid
from ipaddress import IPv4Address, IPv6Address
from pydantic import BaseModel, Field, ConfigDict
from typing import Union

# Type alias for IP addresses
IPAddress = Union[IPv4Address, IPv6Address]


class SessionBase(BaseModel):
    """Base session schema with common fields"""
    user_agent: Optional[str] = Field(None, description="Device fingerprinting and security visibility")
    ip: Optional[IPAddress] = Field(None, description="IP address for suspicious activity detection")


class SessionCreate(SessionBase):
    """Schema for creating a new session"""
    user_id: UUID = Field(..., description="Owner of the session")
    
    model_config = ConfigDict(
        json_encoders={
            UUID: str,
            IPv4Address: str,
            IPv6Address: str,
        }
    )


class SessionUpdate(BaseModel):
    """Schema for updating session fields"""
    last_seen_at: Optional[datetime] = Field(None, description="Update last activity timestamp")
    revoked_at: Optional[datetime] = Field(None, description="Revoke session (instant logout)")
    user_agent: Optional[str] = None
    ip: Optional[IPAddress] = None
    
    model_config = ConfigDict(
        json_encoders={
            IPv4Address: str,
            IPv6Address: str,
        }
    )


class SessionRevoke(BaseModel):
    """Schema specifically for revoking sessions"""
    revoked_at: datetime = Field(default_factory=datetime.now, description="Timestamp when session was revoked")


class SessionResponse(SessionBase):
    """Schema for session responses (read operations)"""
    sid: UUID = Field(..., description="Unique session identifier")
    user_id: UUID = Field(..., description="Owner of the session")
    created_at: datetime = Field(..., description="When session was created (login time)")
    last_seen_at: datetime = Field(..., description="Last activity timestamp")
    revoked_at: Optional[datetime] = Field(None, description="Session revocation timestamp")
    
    # Computed fields
    is_active: bool = Field(..., description="Whether session is active (not revoked)")
    
    model_config = ConfigDict(
        from_attributes=True,  # Enable ORM mode for SQLAlchemy models
        json_encoders={
            UUID: str,
            IPv4Address: str,
            IPv6Address: str,
            datetime: lambda v: v.isoformat(),
        }
    )
    
    @property
    def session_duration(self) -> Optional[float]:
        """Calculate session duration in seconds"""
        if self.revoked_at:
            return (self.revoked_at - self.created_at).total_seconds()
        return (datetime.now() - self.created_at).total_seconds()


class SessionListResponse(BaseModel):
    """Schema for paginated session lists"""
    sessions: list[SessionResponse]
    total: int
    page: int = 1
    size: int = 50
    has_next: bool = False
    has_prev: bool = False


class SessionSummary(BaseModel):
    """Lightweight session schema for summaries"""
    sid: UUID
    created_at: datetime
    last_seen_at: datetime
    is_active: bool
    user_agent: Optional[str] = None
    
    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={
            UUID: str,
            datetime: lambda v: v.isoformat(),
        }
    )


class SessionFilter(BaseModel):
    """Schema for filtering sessions in queries"""
    user_id: Optional[UUID] = None
    is_active: Optional[bool] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    last_seen_after: Optional[datetime] = None
    ip: Optional[IPAddress] = None
    user_agent_contains: Optional[str] = None


class SessionStats(BaseModel):
    """Schema for session statistics"""
    total_sessions: int
    active_sessions: int
    revoked_sessions: int
    unique_users: int
    average_session_duration: Optional[float] = Field(None, description="Average duration in seconds")
    most_recent_activity: Optional[datetime] = None


# JWT-related schemas for session management
class JWTPayload(BaseModel):
    """JWT payload schema with session information"""
    sid: UUID = Field(..., description="Session identifier")
    user_id: UUID = Field(..., description="User identifier")
    iat: datetime = Field(..., description="Issued at timestamp")
    exp: datetime = Field(..., description="Expiration timestamp")
    
    model_config = ConfigDict(
        json_encoders={
            UUID: str,
            datetime: lambda v: int(v.timestamp()),  # Unix timestamp for JWT
        }
    )


class SessionValidationResult(BaseModel):
    """Result of session validation"""
    is_valid: bool
    session: Optional[SessionResponse] = None
    error: Optional[str] = None
    reason: Optional[str] = Field(None, description="Reason for validation failure")


# Example usage schemas for common operations
class BulkSessionRevoke(BaseModel):
    """Schema for bulk session revocation"""
    user_id: Optional[UUID] = Field(None, description="Revoke all sessions for user")
    exclude_current: bool = Field(True, description="Exclude current session from revocation")
    current_session_id: Optional[UUID] = Field(None, description="Current session to exclude")


class SessionActivity(BaseModel):
    """Schema for session activity updates"""
    sid: UUID
    timestamp: datetime = Field(default_factory=datetime.now)
    activity_type: str = Field(..., description="Type of activity (login, api_call, etc.)")
    details: Optional[dict] = Field(None, description="Additional activity details")


class SessionReadSchema(BaseModel):
    """Schema for reading Session data from the database"""

    sid: uuid.UUID = Field(..., description="Primary key of the session record")
    user_id: uuid.UUID = Field(..., description="ID of the user this session belongs to")
    created_at: datetime = Field(..., description="When the session was created")
    last_seen_at: datetime = Field(..., description="When the session was last seen")
    revoked_at: Optional[datetime] = Field(None, description="When the session was revoked (if applicable)")
    user_agent: Optional[str] = Field(None, description="Browser user agent string")
    ip: Optional[IPAddress] = Field(None, description="IP address of the session")

    class Config:
        from_attributes = True 
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            uuid.UUID: lambda v: str(v)
        }


class SessionCreateSchema(BaseModel):
    """Schema for creating new Session records"""
    
    sid: uuid.UUID = Field(..., description="Primary key of the session record")
    user_id: uuid.UUID = Field(..., description="ID of the user this session belongs to")
    created_at: datetime = Field(..., description="When the session was created")
    last_seen_at: datetime = Field(..., description="When the session was last seen")

    class Config:
        from_attributes = True 
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            uuid.UUID: lambda v: str(v)
        }


class SessionUpdateSchema(BaseModel):
    """Schema for updating Session records"""
    
    created_at: datetime = Field(..., description="When the session was created")
    last_seen_at: datetime = Field(..., description="When the session was last seen")
    revoked_at: Optional[datetime] = Field(None, description="When the session was revoked (if applicable)")
    user_agent: Optional[str] = Field(None, description="Browser user agent string")
    ip: Optional[IPAddress] = Field(None, description="IP address of the session")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        } 