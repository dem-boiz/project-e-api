import base64
from datetime import datetime, timedelta
import hmac
import os
from typing import Optional, List
import hashlib
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from config import EVENT_TOKEN_PEPPER, DEVICE_GRANT_LIMIT
from models.device_grant import DeviceGrant
from repository.device_grant_repository import DeviceGrantRepository
from config.logging_config import get_logger

logger = get_logger("device_grant")

class DeviceGrantService:
    
    def __init__(self, db: AsyncSession):
        assert hasattr(db, "execute"), "db is not an AsyncSession"
        self.repo = DeviceGrantRepository(db)


# load a long random secret from env (do NOT hardcode)

    def generate_event_token(self, bytes_len: int = 32) -> str:
        """Return base64url (no padding) opaque token."""
        raw = os.urandom(bytes_len)  # 32 bytes = 256-bit
        tok = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        return tok

    def hash_event_token(self, token: str) -> str:
        """Deterministic HMAC-SHA256 over the token with a server-side pepper."""
        mac = hmac.new(EVENT_TOKEN_PEPPER, token.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode("ascii")


    async def issue_device_grant(
        self, 
        event_id: uuid.UUID,
        device_id: uuid.UUID,
        created_from_invite_id: Optional[uuid.UUID] = None,
        invite_label: Optional[str] = None
    ) -> tuple[DeviceGrant, str]:
        """
        Issue a new device grant for an event
        Returns both the device grant object and the raw token
        """
        logger.debug(f"Issuing device grant for event: {event_id}")
        
        # Generate token and hash it
        raw_token = self.generate_event_token()
        token_hash = self.hash_event_token(raw_token)

        # Create device grant
        device_grant = DeviceGrant(
            event_id=event_id,
            label=invite_label,
            device_id=device_id,
            token_hash=token_hash,
            expires_at=datetime.now() + timedelta(days=30),  # Default expiration
            issued_at=datetime.now(),
            created_from_invite_id=created_from_invite_id
        )
        
        # Save to database
        saved_grant = await self.repo.create(device_grant)
        logger.info(f"Device grant issued: {saved_grant.id} for event: {event_id}")
        
        return saved_grant, raw_token

    async def validate_device_token(self, token: str, event_id: uuid.UUID) -> bool:
        """
        Validate a device token and return the grant if valid
        Checks: token exists, not expired, not revoked
        Returns True if valid, False otherwise
        """
        logger.debug("Validating device token")
        
        # Hash the provided token
        token_hash = self.hash_event_token(token)
        
        # Get the grant
        device_grant = await self.repo.get_by_token_hash(token_hash)

        if not device_grant:
            logger.warning("No device grant found for token")
            return False

        # Check if revoked
        if device_grant.revoked_at is not None:
            logger.warning(f"Device token revoked: {device_grant.id}")
            return False
        
        if event_id != device_grant.event_id:
            logger.warning("Device token does not match event")
            return False

        logger.debug(f"Device token validated successfully: {device_grant.id}")
        return True

    async def revoke_device_grant(self, device_grant_id: uuid.UUID) -> bool:
        """Revoke a device grant by setting revoked_at timestamp"""
        logger.debug(f"Revoking device grant: {device_grant_id}")
        
        device_grant = await self.repo.get_by_id(device_grant_id)
        if not device_grant:
            logger.warning(f"Device grant not found for revocation: {device_grant_id}")
            return False
        
        if device_grant.revoked_at is not None:
            logger.warning(f"Device grant already revoked: {device_grant_id}")
            return False
        
        # Set revocation timestamp
        device_grant.revoked_at = datetime.utcnow()
        await self.repo.update(device_grant)
        
        logger.info(f"Device grant revoked: {device_grant_id}")
        return True

    async def revoke_all_for_event(self, event_id: uuid.UUID) -> int:
        """Revoke all active device grants for an event"""
        logger.debug(f"Revoking all device grants for event: {event_id}")
        
        grants = await self.get_active_grants_for_event(event_id)
        revoked_count = 0
        
        for grant in grants:
            if await self.revoke_device_grant(grant.id):
                revoked_count += 1
        
        logger.info(f"Revoked {revoked_count} device grants for event: {event_id}")
        return revoked_count

    async def get_active_grants_for_event(self, event_id: uuid.UUID) -> List[DeviceGrant]:
        """Get all active (non-expired, non-revoked) grants for an event"""
        all_grants = await self.repo.get_all_by_event_id(event_id)
        now = datetime.now()
        
        active_grants = [
            grant for grant in all_grants
            if grant.revoked_at is None
        ]
        
        logger.debug(f"Found {len(active_grants)} active grants for event: {event_id}")
        return active_grants

    async def get_active_grants_for_device(self, device_id: uuid.UUID) -> List[DeviceGrant]:
        """Get all active (non-expired, non-revoked) grants for a device"""
        all_grants = await self.repo.get_all_by_device_id(device_id)

        active_grants = [
            grant for grant in all_grants
            if grant.revoked_at is None
        ]

        logger.debug(f"Found {len(active_grants)} active grants for device: {device_id}")
        return active_grants

    async def device_hit_limit(self, device_id: uuid.UUID) -> bool:
        logger.debug(f"Checking if device {device_id} has hit the event limit")
        active_grants = await self.get_active_grants_for_device(device_id)
        return len(active_grants) >= int(DEVICE_GRANT_LIMIT)