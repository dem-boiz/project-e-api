import base64
from datetime import datetime, timedelta
import hmac
import os
from typing import Optional, List
import hashlib
import secrets
import uuid

from models.device_grant import DeviceGrant
from repository.device_grant_repository import DeviceGrantRepository
from config.logging_config import get_logger

logger = get_logger("device_grant")

DEVICE_LIMIT = os.getenv("DEVICE_GRANT_LIMIT", 5)  # Default to 5 if not set
PEPPER = os.environ["EVENT_TOKEN_PEPPER"].encode("utf-8")

class DeviceGrantService:
    
    def __init__(self, repository: DeviceGrantRepository):
        self.repository = repository


# load a long random secret from env (do NOT hardcode)

    def generate_event_token(self, bytes_len: int = 32) -> str:
        """Return base64url (no padding) opaque token."""
        raw = os.urandom(bytes_len)  # 32 bytes = 256-bit
        tok = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        return tok

    def hash_event_token(self, token: str) -> str:
        """Deterministic HMAC-SHA256 over the token with a server-side pepper."""
        mac = hmac.new(PEPPER, token.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode("ascii")


    async def issue_device_grant(
        self, 
        event_id: uuid.UUID,
        device_id: uuid.UUID,
        created_from_otp_id: Optional[str] = None
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
            device_id=device_id,
            token_hash=token_hash,
            expires_at=datetime.now() + timedelta(days=30),  # Default expiration
            issued_at=datetime.now(),
            created_from_otp_id=created_from_otp_id
        )
        
        # Save to database
        saved_grant = await self.repository.create(device_grant)
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
        device_grant = await self.repository.get_by_token_hash(token_hash)

        if not device_grant:
            logger.warning("Device token not found")
            return False
        
        # Check if expired
        if device_grant.expires_at < datetime.now():
            logger.warning(f"Device token expired: {device_grant.id}")
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
        
        device_grant = await self.repository.get_by_id(device_grant_id)
        if not device_grant:
            logger.warning(f"Device grant not found for revocation: {device_grant_id}")
            return False
        
        if device_grant.revoked_at is not None:
            logger.warning(f"Device grant already revoked: {device_grant_id}")
            return False
        
        # Set revocation timestamp
        device_grant.revoked_at = datetime.utcnow()
        await self.repository.update(device_grant)
        
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
        all_grants = await self.repository.get_all_by_event_id(event_id)
        now = datetime.now()
        
        active_grants = [
            grant for grant in all_grants
            if grant.expires_at > now and grant.revoked_at is None
        ]
        
        logger.debug(f"Found {len(active_grants)} active grants for event: {event_id}")
        return active_grants

    async def get_active_grants_for_device(self, device_id: uuid.UUID) -> List[DeviceGrant]:
        """Get all active (non-expired, non-revoked) grants for a device"""
        all_grants = await self.repository.get_all_by_device_id(device_id)
        now = datetime.now()

        active_grants = [
            grant for grant in all_grants
            if grant.expires_at > now and grant.revoked_at is None
        ]

        logger.debug(f"Found {len(active_grants)} active grants for device: {device_id}")
        return active_grants

    async def cleanup_expired_grants(self) -> int:
        """Remove expired grants from the database (cleanup utility)"""
        logger.debug("Starting cleanup of expired device grants")
        
        # This would typically be done with a bulk delete query
        # For now, we'll get all and filter (could be optimized)
        # In a real implementation, you'd add a bulk delete method to the repository
        
        logger.info("Expired device grants cleanup completed")
        return 0  # Placeholder - implement bulk delete in repository if needed

    async def extend_grant_expiration(
        self, 
        device_grant_id: uuid.UUID, 
        additional_hours: int
    ) -> bool:
        """Extend the expiration time of a device grant"""
        logger.debug(f"Extending device grant expiration: {device_grant_id}")
        
        device_grant = await self.repository.get_by_id(device_grant_id)
        if not device_grant:
            return False
        
        if device_grant.revoked_at is not None:
            logger.warning(f"Cannot extend revoked grant: {device_grant_id}")
            return False
        
        # Extend expiration
        device_grant.expires_at += timedelta(hours=additional_hours)
        await self.repository.update(device_grant)
        
        logger.info(f"Extended device grant {device_grant_id} by {additional_hours} hours")
        return True

    async def device_hit_limit(self, device_id: uuid.UUID) -> bool:
        active_grants = await self.get_active_grants_for_device(device_id)
        return len(active_grants) >= int(DEVICE_LIMIT)