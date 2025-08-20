from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from sqlalchemy import and_, delete, or_
from models import RefreshToken
from schema import RefreshTokenSchema, RefreshTokenCreateSchema
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional 
from sqlalchemy import update, func
import logging

logger = logging.getLogger(__name__)
class RefreshTokenRepository:
    def __init__(self, RefreshToken: AsyncSession):
        self.RefreshToken = RefreshToken
    
    async def create_refresh_token(self, token_data: RefreshTokenCreateSchema) -> RefreshTokenSchema:
        """Create and store a new RefreshToken record."""
        
        new_token = RefreshToken(
            jti=token_data.jti,
            user_id=token_data.user_id,
            sid=token_data.sid,
            expires_at=token_data.expires_at,
            issued_at=token_data.issued_at,
            used_at=None,
            revoked_at=None,
            csrf_hash=token_data.csrf_hash
        )
        self.RefreshToken.add(new_token)
        await self.RefreshToken.commit()
        await self.RefreshToken.refresh(new_token)
        return RefreshTokenSchema(
            jti=new_token.jti,
            user_id=new_token.user_id,
            sid=new_token.sid,
            expires_at=new_token.expires_at,
            issued_at=new_token.issued_at,
            used_at=new_token.used_at,
            revoked_at=new_token.revoked_at,
            csrf_hash=new_token.csrf_hash
        )
    
    async def get_refresh_token_by_jti(self, jti: str) -> RefreshToken | None:
        """Retrieve a RefreshToken record by jti."""
        try:
            result = await self.RefreshToken.execute(
                select(RefreshToken).where(
                    RefreshToken.jti == jti,
                    or_(
                        RefreshToken.used_at.is_(None),
                        RefreshToken.revoked_at.is_(None)
                    )
                )
            )
            token_record = result.scalar_one()
            return token_record
        except NoResultFound:
            return None
        
    async def expire_refresh_token_in_db(self, jti: uuid.UUID) -> bool:
        """Mark a refresh token as expired by setting its expires_at to the past."""
        try:
            result = await self.RefreshToken.execute(
                update(RefreshToken)
                .where(RefreshToken.jti == jti)
                .values(
                    expires_at=func.now() - func.interval('1 hour')  # Set to 1 hour ago
                )
            ) 
            # Commit the transaction
            await self.RefreshToken.commit()
        
            # Check if any rows were affected
            return result.rowcount > 0
        except Exception:
            return False
    
    async def mark_refresh_token_as_used(self, old_jti: uuid.UUID, new_jti: uuid.UUID) -> bool:
        """Mark a refresh token as used and set its replacement JTI."""
        try:
            result = await self.RefreshToken.execute(
                update(RefreshToken)
                .where(RefreshToken.jti == old_jti)
                .values(
                    used_at=func.now(),
                    replaced_by_jti=new_jti
                )
            ) 
            # Commit the transaction
            await self.RefreshToken.commit()
        
            # Check if any rows were affected
            return result.rowcount > 0
        except Exception:
            return False      
        
    async def get_all_refresh_tokens_by_sid(self, session_id: uuid.UUID) -> list[RefreshToken]:
        try:
            result = await self.RefreshToken.execute(select(RefreshToken).where(
                RefreshToken.sid == session_id
            ))
            
            return result.scalars().all()
        except Exception as e:  
            return []
        
    async def delete_all_refresh_tokens_by_sid(self, sid: uuid.UUID) -> bool:
        try:
            token_list = await self.get_all_refresh_tokens_by_sid(sid)
            
            # Delete token records from the list
            if not token_list:
                return True  # No tokens to delete, consider it successful
            
            for token in token_list:
                await self.RefreshToken.delete(token)
                await self.RefreshToken.commit()
            
            return True
            
        except Exception as e:
            raise Exception(f"Failed to delete refresh tokens for sid {sid}: {e}")
        
    async def delete_all_refresh_tokens_by_user_id(self, user_id: uuid.UUID) -> bool:
        try:
            logger.info(f"Attempting to delete all refresh tokens for user_id: {user_id}")
            
            result = await self.RefreshToken.execute(
                delete(RefreshToken).where(RefreshToken.user_id == user_id)
            )
            
            await self.RefreshToken.commit()
            rows_affected = result.rowcount
            
            logger.info(f"Deleted {rows_affected} refresh tokens for user_id: {user_id}")
            return rows_affected > 0
            
        except Exception as e:
            await self.RefreshToken.rollback()
            logger.error(f"Failed to delete refresh tokens for user_id {user_id}: {e}")
            return False