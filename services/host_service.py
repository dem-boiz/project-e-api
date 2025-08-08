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
        # Return a copy without password_hash to avoid modifying the DB object
        return self._sanitize_host_response(host)

    def _sanitize_host_response(self, host: Host, include_password: bool = False) -> Host:
        """Create a copy of the host object without sensitive data"""
        if include_password:
            return host
        
        # Create a new Host object with the same data but without password_hash
        sanitized_host = Host(
            id=host.id,
            host_number=host.host_number,
            company_name=host.company_name,
            email=host.email,
            password_hash=None,  # Explicitly exclude password hash
            created_at=host.created_at
        )
        return sanitized_host

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
    
    async def get_host_by_email(self, email: str, includePassword = False) -> Optional[Host]:
        host = await self.repo.get_host_by_email(email)
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        return self._sanitize_host_response(host, includePassword)

    async def get_host_by_id(self, host_id: uuid.UUID, includePassword = False) -> Optional[Host]:
        host = await self.repo.get_host_by_id(host_id)
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        return self._sanitize_host_response(host, includePassword)

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
        return self._sanitize_host_response(updated_host)