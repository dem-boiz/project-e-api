from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from models import UserEventAccess
from schema import UserEventAccessReadSchema, UserEventAccessCreateSchema
import uuid
from datetime import datetime


class UserEventAccessRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_user_event_access(self, user_event_access: UserEventAccess) -> UserEventAccessReadSchema:
        """Create and store a new UserEventAccess record."""
        self.session.add(user_event_access)
        await self.session.commit()
        await self.session.refresh(user_event_access)
        return UserEventAccessReadSchema(user_id=user_event_access.user_id,
                                        event_id=user_event_access.event_id,
                                        invite_id=user_event_access.invite_id,
                                        revoked_at=user_event_access.revoked_at,
                                        granted_at=user_event_access.granted_at)

    async def get_user_event_access_by_user_and_event(self, user_id: uuid.UUID, event_id: uuid.UUID) -> UserEventAccess | None:
        """Retrieve a UserEventAccess record by user_id and event_id."""
        try:
            result = await self.session.execute(
                select(UserEventAccess).where(
                    UserEventAccess.user_id == user_id,
                    UserEventAccess.event_id == event_id,
                    UserEventAccess.is_deleted == False
                )
            )
            access = result.scalar_one()
            return access
        except NoResultFound:
            return None