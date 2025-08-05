from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from models.otp import OTP
import uuid
from datetime import datetime


class OTPRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_otp(self, OTP: OTP) -> None:
        """Create and store a new OTP record."""
        self.session.add(OTP)
        await self.session.commit()
        await self.session.refresh(OTP)

    async def get_otp_by_code(self, otp_code: str) -> OTP | None:
        """Retrieve an OTP record by its unique OTP code."""
        try:
            result = await self.session.execute(
                select(OTP).where(OTP.otp_code == otp_code)
            )
            otp = result.scalar_one()
            return otp
        except NoResultFound:
            return None
        
    async def delete_otp_by_code(self, otp_code: str) -> bool:
        """Delete an OTP record by its unique OTP code. Returns True if deleted, False if not found."""
        try:
            result = await self.session.execute(
                select(OTP).where(OTP.otp_code == otp_code)
            )
            otp = result.scalar_one()
            await self.session.delete(otp)
            await self.session.commit()
            return True
        except NoResultFound:
            return False
        
    async def mark_otp_used(self, otp_id: uuid.UUID) -> bool:
        """Mark the OTP as used by setting `used` flag to True."""
        otp = await self.session.get(OTP, otp_id)
        if otp is None:
            return False
        otp.used = True
        await self.session.commit()
        return True

    async def delete_expired_otps(self, current_time: datetime) -> int:
        """Delete all OTP records expired before current_time. Returns number deleted."""
        result = await self.session.execute(
            select(OTP).where(OTP.expires_at < current_time)
        )
        expired_otps = result.scalars().all()
        count = len(expired_otps)
        for otp in expired_otps:
            await self.session.delete(otp)
        await self.session.commit()
        return count
