import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException
from repository import HostRepository
from models import Host
from schema import HostCreateSchema, HostUpdateSchema
from config.logging_config import get_logger

logger = get_logger("service.host")

class HostService:
    def __init__(self, db: AsyncSession):
        self.repo = HostRepository(db)

    async def create_host(self, data: HostCreateSchema) -> Host:
        # Check if host with email already exists
        logger.info(f"Checking if host exists with email '{data.email}' and name '{data.company_name}'")
        existing = await self.repo.get_host_by_email(email=data.email)
        if existing:
            logger.warning(f"Host creation failed: Host already exists with email '{data.email}'")
            raise ValueError("Host already exists with this email.") 
        host = await self.repo.create_host(data)
        logger.info(f"Host created successfully: {host.email}")
        # Return a copy without password_hash to avoid modifying the DB object
        return self._sanitize_host_response(host)

    def _sanitize_host_response(self, host: Host, include_password: bool = False) -> Host:
        """Create a copy of the host object without sensitive data"""
        if include_password:
            logger.debug("Including password in _sanitize_host_response()")
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
        logger.debug(f"Attempting to delete host with id '{host_id}'")
        host = await self.repo.get_host_by_id(host_id)
        if not host:
            logger.warning(f"Host deletion failed: Host not found with ID '{host_id}'")
            raise HTTPException(status_code=404, detail="Host not found")
        await self.repo.delete_host_by_id(host_id)
        logger.info(f"Host with id '{host_id}' successfully deleted")
        return True
    
    async def delete_host_by_email(self, email: str) -> bool:
        logger.debug(f"Attempting to delete host with email '{email}'")
        host = await self.repo.get_host_by_email(email)
        if not host:
            logger.warning(f"Host deletion failed: Host not found with email '{email}'")
            raise HTTPException(status_code=404, detail="Host not found")
        
        await self.repo.delete_host_by_email(email)
        logger.info(f"Host with email '{email}' successfully deleted")
        return True
    
    async def get_host_by_email(self, email: str, includePassword = False) -> Optional[Host]:
        logger.debug(f"Attempting to retrieve host with email '{email}'")
        host = await self.repo.get_host_by_email(email)
        if not host:
            logger.warning(f"Host retrieval failed: Host not found with email '{email}'")
            raise HTTPException(status_code=404, detail="Host not found")
        sanitized_response = self._sanitize_host_response(host, includePassword)
        logger.debug(f"Host retrieved successfully: {sanitized_response.email}")
        return sanitized_response

    async def get_host_by_id(self, host_id: uuid.UUID, includePassword = False) -> Optional[Host]:
        logger.debug(f"Attempting to retrieve host with ID '{host_id}'")
        host = await self.repo.get_host_by_id(host_id)
        if not host:
            logger.warning(f"Host retrieval failed: Host not found with ID '{host_id}'")
            raise HTTPException(status_code=404, detail="Host not found")
        sanitized_response = self._sanitize_host_response(host, includePassword)
        logger.debug(f"Host retrieved successfully: {sanitized_response.email}")
        return sanitized_response

    async def update_host_service(self, host_id: uuid.UUID, data: HostUpdateSchema) -> Host:
        # Check if the host exists
        logger.debug(f"Attempting to update host with ID '{host_id}'")
        host = await self.repo.get_host_by_id(host_id)
        if not host:
            logger.warning(f"Host update failed: Host not found with ID '{host_id}'")
            raise ValueError("Host with the specified ID does not exist.")

        # Update only the fields provided in data
        for key, value in data.model_dump(exclude_unset=True).items():
            if key == "email":
                # If email is being updated, we need to check if it already exists
                existing_host = await self.repo.get_host_by_email(value)
                if existing_host and existing_host.id != host.id:
                    logger.warning(f"Host update failed: Email '{value}' is already in use. Will keep existing email '{host.email}'")
                    raise HTTPException(status_code=409, detail="Email is already in use by another host.")
            if (key != 'password'):
                logger.debug(f"Updating host field '{key}' to '{value}'")
                
            setattr(host, key, value)

        # Call repo update method (which you implement similar to update_host shown before)
        updated_host = await self.repo.update_host(host_id, data)
        logger.debug(f"Host '{host_id}' updated successfully")
        sanitized_host = self._sanitize_host_response(updated_host)
        return sanitized_host