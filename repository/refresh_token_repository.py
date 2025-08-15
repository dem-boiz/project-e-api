from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from sqlalchemy import and_, or_
from models import RefreshToken
from schema import RefreshTokenSchema, RefreshTokenCreate, RefreshTokenUpdate
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional


class RefreshTokenRepository:
    def __init__(self, RefreshToken: AsyncSession):
        self.RefreshToken = RefreshToken
    
    async def create_refresh_token(self, token_data: RefreshTokenCreate) -> RefreshTokenSchema:
        """Create and store a new RefreshToken record."""
        
        new_token = RefreshToken(
            jti=token_data.jti,
            user_id=token_data.user_id,
            sid=token_data.sid,
            expires_at=token_data.expires_at,
            created_at=token_data.created_at,
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
            created_at=new_token.created_at,
            used_at=new_token.used_at,
            revoked_at=new_token.revoked_at,
            csrf_hash=new_token.csrf_hash
        )