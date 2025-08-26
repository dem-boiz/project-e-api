import random
import string
from datetime import datetime, timedelta
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from models.otp import OTP
from models.event import Event
from schema import OTPCreateRequest, OTPDeleteRequest   
from fastapi import HTTPException
from repository import OTPRepository
async def generate_unique_otp_code(repo: OTPRepository, length: int = 6) -> str:
        """Generate a unique OTP code not present in DB."""
        chars = string.digits
        max_attempts = 10
        for _ in range(max_attempts):
            code = ''.join(random.choices(chars, k=length))
            existing = await repo.get_otp_by_code(code)
            if existing is None:
                return code
        raise Exception("Failed to generate unique OTP code after multiple attempts")


class OTPService:
    def __init__(self, db: AsyncSession): 
        assert hasattr(db, "execute"), "db is not an AsyncSession"
        self.repo = OTPRepository(db) 
    
    async def generate_otp(
        self, 
        otp_data: OTPCreateRequest 
    ) -> OTP:
        otp_code = await generate_unique_otp_code(self.repo)
        expires_at = datetime.now() + timedelta(minutes=10) # TODO: set this to an env variable?

        otp_object = OTP(
            email=otp_data.email,
            label=otp_data.label,
            event_id=otp_data.event_id,
            otp_code=otp_code,
            expires_at=expires_at,
            created_at=datetime.now(),
            issued_by_host_id=otp_data.host_id
            )
        await self.repo.create_otp(otp_object) 
        return otp_object
    
    async def delete_otp(self, otp_code: str) -> bool:
        deleted = await self.repo.delete_otp_by_code(otp_code)
        if not deleted:
            raise HTTPException(status_code=404, detail="OTP not found")
        return True

    async def validate_otp(self, otp_code: str) -> uuid.UUID:
        """Validate the OTP code for a specific event by checking its existence and status."""
        results = await self.repo.get_otp_where(
            otp_code=otp_code,
            used=False,
        )
        
        otp = results[0] if results else None

        if not otp:
            raise HTTPException(status_code=404, detail="OTP not found")

        if otp.expires_at <= datetime.now():
            raise HTTPException(status_code=400, detail="OTP has expired")

        marked_used = await self.repo.mark_otp_used(otp.id)

        if not marked_used:
            raise HTTPException(status_code=500, detail="Failed to mark OTP as used")
        return otp.event_id