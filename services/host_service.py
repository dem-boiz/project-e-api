import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException
from repository import HostRepository
from models import Host
from schema import HostCreateSchema, HostUpdateSchema


class HostService:
    def __init__(self, db: AsyncSession):
        self.repo = HostRepository(db)

    async def create_host(self, data: HostCreateSchema) -> Host:
        #Check if host with email already exists
        existing = await self.repo.get_host_by_email(email=data.email)
        if existing:
            raise ValueError("Host already exists with this email.") 
        
        host = await self.repo.create_host(data)
        host.password_hash = None  # Don't return password hash, security risk
        return host

    async def delete_host_by_id(self, host_id: uuid.UUID) -> bool:
        host = await self.repo.get_host_by_id(host_id)
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        
        return await self.repo.delete_host_by_id(host_id)
    
    async def delete_host_by_email(self, email: str) -> bool:
        host = await self.repo.get_host_by_email(email)
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        
        return await self.repo.delete_host_by_email(email)
    
    async def get_host_by_email(self, email: str) -> Optional[Host]:
        host = await self.repo.get_host_by_email(email)
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")   
        host.password_hash = None
        return host

    async def get_host_by_id(self, host_id: uuid.UUID) -> Optional[Host]:
        host = await self.repo.get_host_by_id(host_id)
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        host.password_hash = None
        return host

    async def update_host_service(self, host_id: uuid.UUID, data: HostUpdateSchema) -> Host:
        # Check if the host exists
        host = await self.repo.get_host_by_id(host_id)
        if not host:
            raise ValueError("Host with the specified ID does not exist.")

        # Update only the fields provided in data
        for key, value in data.dict(exclude_unset=True).items():
            setattr(host, key, value)

        # Call repo update method (which you implement similar to update_host shown before)
        updated_host = await self.repo.update_host(host_id, data)
        updated_host.password_hash = None
        return updated_host