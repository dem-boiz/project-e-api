from datetime import datetime
from typing import Optional, List
import uuid

from models.guest_device import GuestDevice
from repository.guest_device_repository import GuestDeviceRepository
from config.logging_config import get_logger
from fastapi import HTTPException, status

logger = get_logger("guest_device")


class GuestDeviceService:
    
    def __init__(self, repository: GuestDeviceRepository):
        self.repository = repository

    async def create_guest_device(self, guest_device_id: Optional[uuid.UUID] = None) -> GuestDevice:
        """
        Create a new guest device with error handling and duplicate checking
        """
        try:
            # If ID is provided, check for duplicates
            if guest_device_id:
                existing_device = await self.repository.get_by_id(guest_device_id)
                if existing_device:
                    logger.warning(f"Attempted to create duplicate guest device: {guest_device_id}")
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"Guest device with ID {guest_device_id} already exists"
                    )

            # Create new guest device
            now = datetime.now()
            guest_device = GuestDevice(
                id=guest_device_id or uuid.uuid4(),
                last_seen_at=now
            )
            
            logger.debug(f"Creating new guest device: {guest_device.id}")
            created_device = await self.repository.create(guest_device)
            logger.info(f"Guest device created successfully: {created_device.id}")
            
            return created_device
            
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            logger.error(f"Error creating guest device: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create guest device"
            )

    async def get_guest_device_by_id(self, guest_device_id: uuid.UUID) -> GuestDevice:
        """
        Get guest device by ID with error handling
        """
        try:
            logger.debug(f"Retrieving guest device: {guest_device_id}")
            
            guest_device = await self.repository.get_by_id(guest_device_id)
            if not guest_device:
                logger.warning(f"Guest device not found: {guest_device_id}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Guest device with ID {guest_device_id} not found"
                )
            
            logger.debug(f"Guest device retrieved successfully: {guest_device_id}")
            return guest_device
            
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            logger.error(f"Error retrieving guest device {guest_device_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve guest device"
            )

    async def get_all_guest_devices(self) -> List[GuestDevice]:
        """
        Get all guest devices with error handling
        """
        try:
            logger.debug("Retrieving all guest devices")
            
            guest_devices = await self.repository.get_all()
            logger.debug(f"Retrieved {len(guest_devices)} guest devices")
            
            return guest_devices
            
        except Exception as e:
            logger.error(f"Error retrieving all guest devices: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve guest devices"
            )

    async def update_guest_device_last_seen(self, guest_device_id: uuid.UUID) -> GuestDevice:
        """
        Update guest device last_seen_at timestamp with error handling
        """
        try:
            logger.debug(f"Updating last seen for guest device: {guest_device_id}")
            
            # Get existing device
            guest_device = await self.get_guest_device_by_id(guest_device_id)
            
            # Update last seen timestamp
            guest_device.last_seen_at = datetime.now()
            
            # Save changes
            updated_device = await self.repository.update(guest_device)
            logger.info(f"Guest device last seen updated: {guest_device_id}")
            
            return updated_device
            
        except HTTPException:
            # Re-raise HTTP exceptions (including 404 from get_guest_device_by_id)
            raise
        except Exception as e:
            logger.error(f"Error updating guest device {guest_device_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update guest device"
            )

    async def delete_guest_device(self, guest_device_id: uuid.UUID) -> bool:
        """
        Delete guest device with error handling
        """
        try:
            logger.debug(f"Deleting guest device: {guest_device_id}")
            
            # Check if device exists first
            await self.get_guest_device_by_id(guest_device_id)
            
            # Delete the device
            deleted = await self.repository.delete(guest_device_id)
            
            if deleted:
                logger.info(f"Guest device deleted successfully: {guest_device_id}")
            else:
                logger.warning(f"Failed to delete guest device: {guest_device_id}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to delete guest device"
                )
            
            return deleted
            
        except HTTPException:
            # Re-raise HTTP exceptions (including 404 from get_guest_device_by_id)
            raise
        except Exception as e:
            logger.error(f"Error deleting guest device {guest_device_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete guest device"
            )

    async def touch_guest_device(self, guest_device_id: uuid.UUID) -> GuestDevice:
        """
        Touch a guest device (update last_seen_at) or create if doesn't exist
        """
        try:
            logger.debug(f"Touching guest device: {guest_device_id}")
            
            # Try to get existing device
            try:
                guest_device = await self.repository.get_by_id(guest_device_id)
                if guest_device:
                    # Update existing device
                    return await self.update_guest_device_last_seen(guest_device_id)
            except:
                # Device doesn't exist, will create below
                pass
            
            # Create new device if it doesn't exist
            logger.debug(f"Guest device not found, creating new one: {guest_device_id}")
            return await self.create_guest_device(guest_device_id)
            
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            logger.error(f"Error touching guest device {guest_device_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to touch guest device"
            )
