from collections.abc import Sequence
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from models import UserGrant
from schema import UserGrantReadSchema, UserGrantCreateSchema
import uuid
from datetime import datetime


class UserGrantRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_user_grant(self, user_grant: UserGrant) -> UserGrantReadSchema:
        """Create and store a new UserGrant record."""
        self.session.add(user_grant)
        await self.session.commit()
        await self.session.refresh(user_grant)
        return UserGrantReadSchema(**user_grant.__dict__)

    async def get_active_user_grants_by_user_and_event(self, user_id: uuid.UUID, event_id: uuid.UUID) -> Sequence[UserGrant]:
        """Retrieve a UserGrant record by user_id and event_id."""
        result = await self.session.execute(
            select(UserGrant).where(
                UserGrant.user_id == user_id,
                UserGrant.event_id == event_id,
                UserGrant.revoked_at == None  # Active grants only
            )
        )

        return result.scalars().all()

    async def get_active_grants_by_user(self, user_id: uuid.UUID) -> int:
        """Retrieve all active UserGrant records by user_id."""
        result = await self.session.execute(
            select(UserGrant).where(
                UserGrant.user_id == user_id,
                UserGrant.revoked_at == None  # Active grants only
            )
        )
        return len(result.scalars().all())

    async def get_active_grants_count(self, user_id: uuid.UUID, event_id: uuid.UUID) -> int:
        """Retrieve the count of active UserGrant records by user_id and event_id."""
        result = await self.get_active_user_grants_by_user_and_event(user_id, event_id)
        return len(result)