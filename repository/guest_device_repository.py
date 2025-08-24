from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import Sequence, select
from models.guest_device import GuestDevice
from typing import Optional, Sequence
import uuid


class GuestDeviceRepository:
    
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, guest_device: GuestDevice) -> GuestDevice:
        """Create a new guest device"""
        self.db.add(guest_device)
        await self.db.commit()
        await self.db.refresh(guest_device)
        return guest_device

    async def get_by_id(self, guest_device_id: uuid.UUID) -> Optional[GuestDevice]:
        """Get guest device by ID"""
        query = select(GuestDevice).where(GuestDevice.id == guest_device_id)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_all(self) -> Sequence[GuestDevice]:
        """Get all guest devices"""
        query = select(GuestDevice)
        result = await self.db.execute(query)
        return result.scalars().all()

    async def update(self, guest_device: GuestDevice) -> GuestDevice:
        """Update an existing guest device"""
        await self.db.commit()
        await self.db.refresh(guest_device)
        return guest_device

    async def delete(self, guest_device_id: uuid.UUID) -> bool:
        """Delete a guest device"""
        guest_device = await self.get_by_id(guest_device_id)
        if guest_device:
            await self.db.delete(guest_device)
            await self.db.commit()
            return True
        return False
