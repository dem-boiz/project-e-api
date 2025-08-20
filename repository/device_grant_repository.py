from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models.device_grant import DeviceGrant
from typing import Optional, List
import uuid


class DeviceGrantRepository:
    
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, device_grant: DeviceGrant) -> DeviceGrant:
        """Create a new device grant"""
        self.db.add(device_grant)
        await self.db.commit()
        await self.db.refresh(device_grant)
        return device_grant

    async def get_by_id(self, device_grant_id: uuid.UUID) -> Optional[DeviceGrant]:
        """Get device grant by ID"""
        query = select(DeviceGrant).where(DeviceGrant.id == device_grant_id)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_by_token_hash(self, token_hash: str) -> Optional[DeviceGrant]:
        """Get device grant by token hash"""
        query = select(DeviceGrant).where(DeviceGrant.token_hash == token_hash)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_all_by_event_id(self, event_id: uuid.UUID) -> List[DeviceGrant]:
        """Get all device grants for an event"""
        query = select(DeviceGrant).where(DeviceGrant.event_id == event_id)
        result = await self.db.execute(query)
        return result.scalars().all()

    async def update(self, device_grant: DeviceGrant) -> DeviceGrant:
        """Update an existing device grant"""
        await self.db.commit()
        await self.db.refresh(device_grant)
        return device_grant

    async def delete(self, device_grant_id: uuid.UUID) -> bool:
        """Delete a device grant"""
        device_grant = await self.get_by_id(device_grant_id)
        if device_grant:
            await self.db.delete(device_grant)
            await self.db.commit()
            return True
        return False
