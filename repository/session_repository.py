from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from sqlalchemy import and_, or_
from models import Session
from schema import SessionReadSchema, SessionCreateSchema 
import uuid
from datetime import datetime, timedelta, timezone
from typing import Sequence
from sqlalchemy import update, func 
import uuid
import logging

logger = logging.getLogger(__name__)
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

    async def get_session_by_sid(self, sid: uuid.UUID) -> Session | None:
        """Retrieve a Session record by sid."""
        try:
            result = await self.session.execute(
                select(Session).where(
                    Session.sid == sid
                )
            )
            session_record = result.scalar_one()
            return session_record
        except NoResultFound:
            return None 

    async def get_active_sessions_by_user(self, user_id: uuid.UUID) -> Sequence[Session]:
        """Retrieve all active sessions for a specific user."""
        result = await self.session.execute(
            select(Session).where(
                Session.user_id == user_id,
                Session.is_active == True
            ).order_by(Session.last_seen_at.desc())
        )
        return result.scalars().all()

    async def get_all_sessions_by_user(self, user_id: uuid.UUID) -> Sequence[Session]:
        """Retrieve all sessions (active and inactive) for a specific user."""
        result = await self.session.execute(
            select(Session).where(
                Session.user_id == user_id
            ).order_by(Session.created_at.desc())
        )
        return result.scalars().all()

    async def update_session_activity(self, session_id: uuid.UUID, last_seen_at: datetime = None) -> Session | None:
        """Update the last_seen_at timestamp for a session."""
        if last_seen_at is None:
            last_seen_at = datetime.now(timezone.utc)
            
        session_record = await self.get_session_by_sid(session_id)
        if session_record:
            session_record.last_seen_at = last_seen_at
            session_record.updated_at = datetime.now(timezone.utc)
            await self.session.commit()
            await self.session.refresh(session_record)
        return session_record

    async def invalidate_session(self, session_id: uuid.UUID) -> bool:
        """Invalidate (deactivate) a specific session."""
        session_record = await self.get_session_by_sid(session_id)
        if session_record is None:
            return False
        if session_record: 
            session_record.revoked_at = datetime.now(timezone.utc)
            await self.session.commit()
            await self.session.refresh(session_record)
            return True
        return False 

    async def revoke_all_active_sessions_by_user_id(self, user_id: uuid.UUID) -> bool:
        try:
            logger.info(f"Attempting to revoke sessions for user_id: {user_id}")
            
            result = await self.session.execute(
                update(Session)
                .where(
                    (Session.user_id == user_id) & 
                    (Session.revoked_at.is_(None))
                )
                .values(revoked_at=func.now())
            )
            
            await self.session.commit()
            rows_affected = result.rowcount
            
            logger.info(f"Revoked {rows_affected} sessions for user_id: {user_id}")
            return rows_affected > 0
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to revoke sessions for user_id {user_id}: {e}")
            return False

    async def cleanup_expired_sessions(self) -> int:
        """Remove or deactivate expired sessions."""
        result = await self.session.execute(
            select(Session).where(Session.is_active == True))
        expired_sessions = result.scalars().all()
        
        count = 0
        for session_record in expired_sessions:
            session_record.is_active = False # TODO: check with simon... is_active is a property that returns 'revokedAt is None', is this correct?
            session_record.last_seen_at = datetime.now(timezone.utc)
            count += 1
            
        if count > 0:
            await self.session.commit()
            
        return count

    async def extend_session_expiry(self, session_id: uuid.UUID, extension_hours: int = 24) -> Session | None:
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

    async def get_recent_sessions(self, user_id: uuid.UUID, limit: int = 10) -> Sequence[Session]:
        """Get the most recent sessions for a user."""
        result = await self.session.execute(
            select(Session).where(
                Session.user_id == user_id
            ).order_by(Session.last_seen_at.desc()).limit(limit)
        )
        return result.scalars().all()