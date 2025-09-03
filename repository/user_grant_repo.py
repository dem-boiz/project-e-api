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
        return UserGrantReadSchema(user_id=user_grant.user_id,
                                        event_id=user_grant.event_id,
                                        invite_id=user_grant.created_from_invite_id,
                                        revoked_at=user_grant.revoked_at,
                                        granted_at=user_grant.issued_at)

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