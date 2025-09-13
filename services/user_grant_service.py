import uuid
from typing import Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select 
from sqlalchemy.exc import NoResultFound
from models import UserGrant
from fastapi import HTTPException, status
from repository import UserGrantRepository
from schema import UserGrantReadSchema, UserGrantCreateSchema
from config import USER_GRANT_LIMIT
from config.logging_config import get_logger

logger = get_logger("service.user_grants")
class UserGrantService:
    def __init__(self, db: AsyncSession):
        self.repo = UserGrantRepository(db)

    async def create_user_grant(self, user_grant: UserGrantCreateSchema) -> UserGrantReadSchema:
        # Check if the grant record already exists
        existing = await self.repo.get_active_user_grant_by_user_and_event(user_grant.user_id, user_grant.event_id)
        if existing:    
            raise ValueError("Access record already exists for this user and event.")
        # Create a new UserGrant instance with attributes from the schema
        new_access = UserGrant(
            user_id=user_grant.user_id,
            event_id=user_grant.event_id,
            access_type=user_grant.access_type,
            issued_at=user_grant.issued_at,
            created_from_invite_id=user_grant.created_from_invite_id
        )
        return await self.repo.create_user_grant(new_access)

    async def get_active_grants_by_user_id(self, user_id: uuid.UUID) -> list[UserGrantReadSchema]:
        logger.info('Fetching active grants for user_id: %s', user_id)
        grants = await self.repo.get_active_grants_by_user(user_id)
        logger.info('Found %d active grants for user_id: %s', len(grants), user_id)
        return [UserGrantReadSchema.model_validate(grant) for grant in grants]


    async def get_active_grants_for_event(self, event_id: uuid.UUID) -> list[UserGrantReadSchema]:
        logger.info('Fetching active grants for event_id: %s', event_id)
        grants = await self.repo.get_active_grants_for_event(event_id)
        logger.info('Found %d active grants for event_id: %s', len(grants), event_id)
        return [UserGrantReadSchema.model_validate(grant) for grant in grants]

    async def user_hit_limit(self, user_id: uuid.UUID) -> bool:
        """Check if the user has hit the maximum event limit."""
        return await self.repo.get_active_grants_by_user_count(user_id) >= USER_GRANT_LIMIT
    

    async def revoke_user_grant(self, user_id: uuid.UUID, event_id: uuid.UUID) -> None:
        """Revoke a UserGrant by setting its revoked_at timestamp."""
        grants = await self.repo.revoke_user_grant(user_id, event_id)
        if not grants or len(grants) == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active UserGrant not found for the given user and event.")
        return
