import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select 
from sqlalchemy.exc import NoResultFound
from models import UserEventAccess
from fastapi import HTTPException
from repository import UserEventAccessRepository
from models import UserEventAccess
from schema import UserEventAccessCreateSchema, UserEventAccessReadSchema


class UserEventAccessService:
    def __init__(self, db: AsyncSession):
        self.repo = UserEventAccessRepository(db)

    async def create_user_event_access(self, user_event_access: UserEventAccessCreateSchema) -> UserEventAccessReadSchema:
        # Check if the access record already exists
        existing = await self.repo.get_user_event_access_by_user_and_event(user_event_access.user_id, user_event_access.event_id)
        if existing:    
            raise ValueError("Access record already exists for this user and event.")
        new_access = UserEventAccess(
            user_id=user_event_access.user_id,
            event_id=user_event_access.event_id,
            invite_id=user_event_access.invite_id,
            is_deleted=False
        )
        return await self.repo.create_user_event_access(new_access)
    
    async def get_user_event_access_by_user_and_event(self, user_id: uuid.UUID, event_id: uuid.UUID) -> Optional[UserEventAccessReadSchema]:
        """Retrieve a UserEventAccess record by user_id and event_id."""
        access = await self.repo.get_user_event_access_by_user_and_event(user_id, event_id)
        if not access:
            raise HTTPException(status_code=404, detail="User Event Access not found")
        return UserEventAccessReadSchema.from_orm(access)
    
    async def delete_user_event_access(self, user_id: uuid.UUID, event_id: uuid.UUID) -> None:
        """Soft delete a UserEventAccess record by user_id and event_id."""
        access = await self.repo.get_user_event_access_by_user_and_event(user_id, event_id)
        if not access:
            raise HTTPException(status_code=404, detail="User Event Access not found")
        access.is_deleted = True
        await self.repo.session.commit()

    async def get_user_event_access_by_invite_id(self, invite_id: uuid.UUID) -> Optional[UserEventAccessReadSchema]:
        """Retrieve a UserEventAccess record by invite_id."""
        try:
            result = await self.repo.session.execute(
                select(UserEventAccess).where(
                    UserEventAccess.invite_id == invite_id,
                )
            )
            access = result.scalar_one()
            return access
        except NoResultFound:
            return None