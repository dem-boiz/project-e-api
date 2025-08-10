from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from models import Host
from schema import HostCreateSchema, HostUpdateSchema
import uuid
from datetime import datetime
from typing import Optional
from passlib.context import CryptContext

# Password hashing context - suppress bcrypt version warnings
pwd_context = CryptContext(
    schemes=["bcrypt"], 
    deprecated="auto",
    bcrypt__rounds=10  # The number of hashing rounds. Higher = more secure but slower
)




class HostRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_host(self, data: HostCreateSchema) -> Host:
        """Create a new host with a unique UUID and email."""
        password_hash = pwd_context.hash(data.password)
        new_host = Host(
            email=data.email, 
            company_name=data.company_name, 
            password_hash=password_hash, 
            id=uuid.uuid4(),
            created_at=datetime.now()
        )
        self.session.add(new_host)
        await self.session.commit()
        await self.session.refresh(new_host)
        return new_host
    
    async def delete_host_by_id(self, host_id: uuid.UUID) -> bool:
        """Delete host by id. Returns True if deleted, False if not found."""
        host = await self.get_host_by_id(host_id)
        if host is None:
            return False
        await self.session.delete(host)
        await self.session.commit()
        return True
    
    async def delete_host_by_email(self, email: str) -> bool:
        """Delete host by email. Returns True if deleted, False if not found."""
        host = await self.get_host_by_email(email)
        if host is None:
            return False
        await self.session.delete(host)
        await self.session.commit()
        return True
    
    async def get_host_by_email(self, email: str) -> Host | None:
        """Fetch host by email. Returns None if not found."""
        try:
            result = await self.session.execute(
                select(Host).where(Host.email == email)
            )
            host = result.scalar_one()
            return host
        except NoResultFound:
            return None
        
    async def get_host_by_id(self, host_id: uuid.UUID) -> Host | None:
        """Fetch host by UUID. Returns None if not found."""
        try:
            result = await self.session.execute(
                select(Host).where(Host.id == host_id)
            )
            host = result.scalar_one()
            return host
        except NoResultFound:
            return None
        
    async def update_host(self, host_id: uuid.UUID, data: HostUpdateSchema) -> Optional[Host]:
        try:
            result = await self.session.execute(select(Host).where(Host.id == host_id))
            host = result.scalar_one()

            # Update only fields provided (not None)
            if data.email is not None:
                host.email = data.email
            if data.company_name is not None:
                host.company_name = data.company_name
            if data.password is not None:
                # TODO: hash password and update host.password_hash
                host.password_hash = data.password
            if data.created_at is not None:
                # Assuming created_at is a datetime or ISO string
                if isinstance(data.created_at, str):
                    host.created_at = datetime.fromisoformat(data.created_at)
                else:
                    host.created_at = data.created_at

            await self.session.commit()
            await self.session.refresh(host)
            return host

        except NoResultFound:
            return None