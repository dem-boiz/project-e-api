import random
import string
from datetime import datetime, timedelta
from typing import Sequence
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from models.invite import Invite
from repository.event_repository import EventRepository
from repository.host_repository import HostRepository
from schema.invite_schemas import InviteCreateRequest, InviteUpdateRequest
from fastapi import HTTPException
from repository.invite_repository import InviteRepository
from config.logging_config import get_logger

from config import INVITE_HOUR_EXPIRY, CLIENT_URL
from utils import send_invite_email

logger = get_logger("api.invites")

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

    async def create_invite(self, invite_data: InviteCreateRequest, event_id: uuid.UUID, host_id: uuid.UUID) -> tuple[Invite, str | None]:
        # Validate type
        if invite_data.access_type not in ["guest", "vendor"]:
            raise HTTPException(status_code=400, detail="Invalid invite type")

        # Validate delivery method
        if invite_data.delivery_method not in ["email", "link"]:
            raise HTTPException(status_code=400, detail="Invalid delivery method")

        # Validate email for email delivery
        if invite_data.delivery_method == "email" and not invite_data.email:
            raise HTTPException(status_code=400, detail="Email is required for email delivery")

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
            label=invite_data.label if invite_data.label else f"invite-{random.randint(1000,9999)}",
            event_id=event_id,
            otp_code=invite_code,
            expires_at=expires_at,
            created_at=datetime.now(),
            issued_by_host_id=host_id,
            type=invite_data.access_type
        )

        invite_link = f"{CLIENT_URL}/join-event/{invite_code}"

        if invite_data.delivery_method == "email" and invite_data.email:
            logger.info(f"Sending invite email to {invite_data.email} with code {invite_code}")
            email_result = await send_invite_email(invite_data.email, invite_link)
            if email_result.get("status") == "Invite failed":
                logger.error(f"Failed to send invite email: {email_result.get('error')}")
                raise HTTPException(status_code=500, detail="Failed to send invite email")
        else:
            logger.info(f"Invite link generated for {invite_data.email} with code {invite_code}")

        await self.repo.create_invite(invite_object)
        return invite_object, invite_link if invite_data.delivery_method == "link" else None

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


    async def get_pending_invites_by_event(self, event_id: uuid.UUID) -> Sequence[Invite]:
        invites = await self.repo.get_invites_by_event_id(event_id)
        logger.debug(f'Pending invites for event {event_id}: {invites}')
        return [invite for invite in invites if invite.used_at is None]



    async def delete_pending_invite_by_event_id(self, event_id: uuid.UUID, invite_id: uuid.UUID) -> bool:


        deleted = await self.repo.delete_pending_invite_by_event_id(event_id, invite_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Pending invite not found")
        return True

    async def validate_invite(self, invite_code: str) -> Invite:
        invite = await self.repo.get_invite_by_code(invite_code)
        if not invite:
            raise HTTPException(status_code=404, detail="Invite not found")
        if invite.expires_at < datetime.now():
            raise HTTPException(status_code=400, detail="Invite has expired")
        
        return invite
    

    async def update_pending_invite_by_event_id(self, update_data: InviteUpdateRequest, event_id: uuid.UUID, invite_id: uuid.UUID) -> Invite:
        invite = await self.repo.get_invite_by_event_id(event_id, invite_id)
        if not invite or invite.used_at is not None:
            # We raise 404 here because used_at invite would not be at the /pending sub-ath
            raise HTTPException(status_code=404, detail="Invite not found")
        if invite.expires_at < datetime.now():
            raise HTTPException(status_code=400, detail="Invite has expired")

        # Update the invite details
        for key, value in update_data.model_dump(exclude_unset=True).items():
            setattr(invite, key, value)

        await self.repo.update_invite(invite)
        return invite
