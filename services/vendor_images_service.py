import base64
import uuid
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException
from repository import VendorImagesRepository, UserRepository
from models import EventVendor
from schema import VendorImagesCreateSchema, VendorImagesReadSchema, VendorImagesDeleteSchema
from config.logging_config import get_logger

logger = get_logger("service.vendor_images")

class VendorImagesService:
    def __init__(self, db: AsyncSession):
        self.event_vendors_repo = VendorImagesRepository(db)
        self.user_repo = UserRepository(db)

    async def add_vendor_image_service(self, data: VendorImagesCreateSchema) -> VendorImagesReadSchema:
        logger.info(f"Adding image for event vendor ID: {data.event_vendor_id}")
        
        new_image = await self.event_vendors_repo.create_vendor_image(data=data)
        logger.info(f"Image added successfully for event vendor ID: {data.event_vendor_id}")
        return new_image
    
    async def get_vendor_image_service(self, image_id: uuid.UUID) -> VendorImagesReadSchema:
        logger.info(f"Retrieving image with ID: {image_id}")
        image = await self.event_vendors_repo.get_vendor_image(image_id=image_id)
        if not image:
            raise HTTPException(status_code=404, detail="Vendor Image not found")  
        return image