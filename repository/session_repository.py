from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from sqlalchemy import and_, or_
from models import Session
from schema import SessionReadSchema, SessionCreateSchema, SessionUpdateSchema
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional


class SessionRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_session(self, session_data: SessionCreateSchema) -> SessionReadSchema:

        """Create and store a new Session record."""
        
        new_session = Session(
            sid=session_data.sid,   
            user_id=session_data.user_id,
            created_at=session_data.created_at,
            last_seen_at=session_data.last_seen_at,
            revoked_at=None,
            user_agent=None,
            ip=None
        )
        self.session.add(new_session)
        await self.session.commit()
        await self.session.refresh(new_session)
        return SessionReadSchema(
            sid=session_data.sid,
            user_id=session_data.user_id,
            created_at=session_data.created_at,
            last_seen_at=session_data.last_seen_at,
            revoked_at=None,
            user_agent=None,
            ip=None
        )

    async def get_session_by_sid(self, sid: str) -> Session | None:
        """Retrieve a Session record by sid."""
        try:
            result = await self.session.execute(
                select(Session).where(
                    Session.sid == sid,
                    Session.is_active == True
                )
            )
            session_record = result.scalar_one()
            return session_record
        except NoResultFound:
            return None 

    async def get_active_sessions_by_user(self, user_id: uuid.UUID) -> List[Session]:
        """Retrieve all active sessions for a specific user."""
        result = await self.session.execute(
            select(Session).where(
                Session.user_id == user_id,
                Session.is_active == True
            ).order_by(Session.last_seen_at.desc())
        )
        return result.scalars().all()

    async def get_all_sessions_by_user(self, user_id: uuid.UUID) -> List[Session]:
        """Retrieve all sessions (active and inactive) for a specific user."""
        result = await self.session.execute(
            select(Session).where(
                Session.user_id == user_id
            ).order_by(Session.created_at.desc())
        )
        return result.scalars().all()

    async def update_session_activity(self, session_id: str, last_seen_at: datetime = None) -> Session | None:
        """Update the last_seen_at timestamp for a session."""
        if last_seen_at is None:
            last_seen_at = datetime.now(timezone.utc)
            
        session_record = await self.get_session_by_session_id(session_id)
        if session_record:
            session_record.last_seen_at = last_seen_at
            session_record.updated_at = datetime.now(timezone.utc)
            await self.session.commit()
            await self.session.refresh(session_record)
        return session_record

    async def invalidate_session(self, session_id: str) -> bool:
        """Invalidate (deactivate) a specific session."""
        session_record = await self.get_session_by_session_id(session_id)
        if session_record:
            session_record.is_active = False
            session_record.updated_at = datetime.now(timezone.utc)
            await self.session.commit()
            return True
        return False

    async def invalidate_all_user_sessions(self, user_id: uuid.UUID, except_session_id: str = None) -> int:
        """Invalidate all sessions for a user, optionally except a specific session."""
        query = select(Session).where(
            Session.user_id == user_id,
            Session.is_active == True
        )
        
        if except_session_id:
            query = query.where(Session.session_id != except_session_id)
            
        result = await self.session.execute(query)
        sessions_to_invalidate = result.scalars().all()
        
        count = 0
        for session_record in sessions_to_invalidate:
            session_record.is_active = False
            session_record.last_seen_at = datetime.now(timezone.utc)
            count += 1
            
        if count > 0:
            await self.session.commit()
            
        return count

    async def cleanup_expired_sessions(self) -> int:
        """Remove or deactivate expired sessions."""
        result = await self.session.execute(
            select(Session).where(Session.is_active == True))
        expired_sessions = result.scalars().all()
        
        count = 0
        for session_record in expired_sessions:
            session_record.is_active = False
            session_record.last_seen_at = datetime.now(timezone.utc)
            count += 1
            
        if count > 0:
            await self.session.commit()
            
        return count

    async def get_sessions_by_ip(self, ip: str, user_id: uuid.UUID = None) -> List[Session]:
        """Get sessions by device info, optionally filtered by user."""
        query = select(Session).where(Session.ip == ip)
        
        if user_id:
            query = query.where(Session.user_id == user_id)
            
        result = await self.session.execute(query.order_by(Session.created_at.desc()))
        return result.scalars().all()

    async def extend_session_expiry(self, session_id: str, extension_hours: int = 24) -> Session | None:
        """Extend the expiry time of a session."""
        session_record = await self.get_session_by_sid(session_id)
        if session_record:
            session_record.expires_at = datetime.now(timezone.utc) + timedelta(hours=extension_hours)
            session_record.updated_at = datetime.now(timezone.utc)
            await self.session.commit()
            await self.session.refresh(session_record)
        return session_record

    async def get_session_count_by_user(self, user_id: uuid.UUID, active_only: bool = True) -> int:
        """Get count of sessions for a user."""
        query = select(Session).where(Session.user_id == user_id)
        
        if active_only:
            query = query.where(Session.is_active == True)
            
        result = await self.session.execute(query)
        return len(result.scalars().all())

    async def get_recent_sessions(self, user_id: uuid.UUID, limit: int = 10) -> List[Session]:
        """Get the most recent sessions for a user."""
        result = await self.session.execute(
            select(Session).where(
                Session.user_id == user_id
            ).order_by(Session.last_seen_at.desc()).limit(limit)
        )
        return result.scalars().all()