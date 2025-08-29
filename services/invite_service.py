import random
import string
from datetime import datetime, timedelta
from typing import Sequence
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from models.invite import Invite
from repository.event_repository import EventRepository
from repository.host_repository import HostRepository
from schema.invite_schemas import InviteCreateRequest
from fastapi import HTTPException
from repository.invite_repository import InviteRepository


from config import INVITE_HOUR_EXPIRY

async def generate_unique_invite_code(repo: InviteRepository, length: int = 6) -> str:
    """Generate a unique invite code not present in DB."""
    chars = string.digits
    max_attempts = 10
    for _ in range(max_attempts):
        code = ''.join(random.choices(chars, k=length))
        existing = await repo.get_invite_by_code(code)
        if existing is None:
            return code
    raise Exception("Failed to generate unique invite code after multiple attempts")

class InviteService:
    def __init__(self, db: AsyncSession):
        assert hasattr(db, "execute"), "db is not an AsyncSession"
        self.repo = InviteRepository(db)
        self.event_repo = EventRepository(db)
        self.host_repo = HostRepository(db)

    async def create_invite(self, invite_data: InviteCreateRequest, event_id: uuid.UUID, host_id: uuid.UUID) -> Invite:
        # Validate type
        if invite_data.type not in ["guest", "vendor"]:
            raise HTTPException(status_code=400, detail="Invalid invite type")
        # Vendor requires email
        if invite_data.type == "vendor" and not invite_data.email:
            raise HTTPException(status_code=400, detail="Vendor invite requires email")
        # Guest requires email or label
        if invite_data.type == "guest" and not (invite_data.email or invite_data.label):
            raise HTTPException(status_code=400, detail="Guest invite requires email or label")
        # Validate event exists
        event = await self.event_repo.get_event_by_id(event_id)
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")
        # Validate host exists
        host = await self.host_repo.get_host_by_id(host_id)
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")

        invite_code = await generate_unique_invite_code(self.repo)
        expires_at = datetime.now() + timedelta(hours=INVITE_HOUR_EXPIRY)
        invite_object = Invite(
            email=invite_data.email,
            label=invite_data.label,
            event_id=event_id,
            otp_code=invite_code,
            expires_at=expires_at,
            created_at=datetime.now(),
            issued_by_host_id=host_id,
            type=invite_data.type
        )
        await self.repo.create_invite(invite_object)
        return invite_object

    async def delete_invite(self, invite_code: str) -> bool:
        deleted = await self.repo.delete_invite_by_code(invite_code)
        if not deleted:
            raise HTTPException(status_code=404, detail="Invite not found")
        return True

    async def get_invite_by_code(self, invite_code: str) -> Invite:
        invite = await self.repo.get_invite_by_code(invite_code)
        if not invite:
            raise HTTPException(status_code=404, detail="Invite not found")
        return invite


    async def get_invites_by_event(self, event_id: uuid.UUID) -> Sequence[Invite]:
        invites = await self.repo.get_invites_by_event_id(event_id)
        return invites


    async def validate_invite(self, invite_code: str) -> Invite:
        invite = await self.repo.get_invite_by_code(invite_code)
        if not invite:
            raise HTTPException(status_code=404, detail="Invite not found")
        if invite.expires_at < datetime.now():
            raise HTTPException(status_code=400, detail="Invite has expired")
        
        return invite
