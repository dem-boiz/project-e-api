import random
import string
from datetime import datetime, timedelta
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
    
    async def generate_otp(self, otp_data: OTPCreateRequest) -> OTP:
        otp_code = await generate_unique_otp_code(self.repo)
        expires_at = datetime.utcnow() + timedelta(minutes=10)

        otp_object = OTP(
            email=otp_data.email,
            event_id=otp_data.event_id,
            otp_code=otp_code,
            expires_at=expires_at)
        await self.repo.create_otp(otp_object) 
        return otp_object
    
    async def delete_otp(self, otp_code: str) -> bool:
        deleted = await self.repo.delete_otp_by_code(otp_code)
        if not deleted:
            raise HTTPException(status_code=404, detail="OTP not found")
        return True

    async def verify_otp(self, email: str, event_id: str, otp_code: str) -> bool:
        otp = await self.repo.get_otp_by_code(otp_code)
        if not otp:
            raise HTTPException(status_code=400, detail="Invalid or expired OTP")

        marked_used = await self.repo.mark_otp_used(otp.id) 
        
        if not marked_used: 
            return False
        return True