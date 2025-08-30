import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from sqlalchemy import and_, delete, or_
from models.invite import Invite
from schema.invite_schemas import InviteCreateRequest
from typing import Sequence
from sqlalchemy import update, func
import logging

logger = logging.getLogger(__name__)
class InviteRepository:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_invite(self, invite: Invite) -> Invite:
        self.db.add(invite)
        await self.db.commit()
        await self.db.refresh(invite)
        return invite
    
    async def get_invite_by_code(self, invite_code: str) -> Invite | None:
        result = await self.db.execute(
            select(Invite).where(Invite.otp_code == invite_code)
        )
        return result.scalar_one_or_none()
    
    async def delete_invite_by_code(self, invite_code: str) -> bool:
        result = await self.db.execute(
            delete(Invite).where(Invite.otp_code == invite_code)
        )
        await self.db.commit()
        return result.rowcount > 0

    async def get_invites_by_event_id(self, event_id: uuid.UUID) -> Sequence[Invite]:
        result = await self.db.execute(
            select(Invite).where(Invite.event_id == event_id)
        )
        return result.scalars().all()


    async def delete_pending_invite_by_event_id(self, event_id: uuid.UUID, invite_id: uuid.UUID) -> bool:
        result = await self.db.execute(
            delete(Invite).where(Invite.event_id == event_id, Invite.used_at == None, Invite.id == invite_id)
        )
        await self.db.commit()
        return result.rowcount > 0