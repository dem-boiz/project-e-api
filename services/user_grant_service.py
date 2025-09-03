import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select 
from sqlalchemy.exc import NoResultFound
from models import UserGrant
from fastapi import HTTPException, status
from repository import UserGrantRepository
from schema import UserGrantReadSchema, UserGrantCreateSchema
from config import USER_GRANT_LIMIT

class UserGrantService:
    def __init__(self, db: AsyncSession):
        self.repo = UserGrantRepository(db)

    async def create_user_grant(self, user_grant: UserGrantCreateSchema) -> UserGrantReadSchema:
        # Check if the grant record already exists
        existing = await self.repo.get_active_user_grants_by_user_and_event(user_grant.user_id, user_grant.event_id)
        if existing:    
            raise ValueError("Access record already exists for this user and event.")
        new_access = UserGrant(user_grant)
        return await self.repo.create_user_grant(new_access)


    async def delete_user_grant(self, user_id: uuid.UUID, event_id: uuid.UUID) -> None:
        """Soft delete a UserGrant record by user_id and event_id."""
        access = await self.repo.get_user_grant_by_user_and_event(user_id, event_id)
        if not access:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User Grant not found")
        access.is_deleted = True
        await self.repo.session.commit()

    async def user_hit_limit(self, user_id: uuid.UUID, event_id: uuid.UUID) -> bool:
        """Check if the user has hit the maximum event limit."""
        return await self.repo.get_active_grants_count(user_id, event_id) >= USER_GRANT_LIMIT
