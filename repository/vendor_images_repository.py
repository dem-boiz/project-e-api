import base64
from typing import List
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound
from models import VendorImage
from schema import VendorImagesCreateSchema, VendorImagesReadSchema, VendorImagesDeleteSchema
import uuid
from datetime import datetime

class VendorImagesRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_vendor_image(self, data: VendorImagesCreateSchema) -> VendorImagesReadSchema:
        new_event_image = VendorImage(event_vendor_id=data.event_vendor_id, image_data=base64.b64decode(data.image_data))
        self.session.add(new_event_image)
        await self.session.commit()
        await self.session.refresh(new_event_image)
        return VendorImagesReadSchema(event_vendor_id=str(data.event_vendor_id), image_data=data.image_data, created_at=new_event_image.created_at) # type: ignore
 
    async def get_vendor_image(self, image_id: uuid.UUID) -> VendorImagesReadSchema | None:
        try:
            result = await self.session.execute(
                select(VendorImage).where(VendorImage.id == image_id)
            )
            vendor_image = result.scalar_one()
            return VendorImagesReadSchema(event_vendor_id=vendor_image.event_vendor_id, image_data=vendor_image.image_data, created_at=vendor_image.created_at) # type: ignore
        except NoResultFound:
            return None
        
    async def get_images_for_event_vendor(self, event_vendor_id: uuid.UUID) -> List[VendorImagesReadSchema]:
        result = await self.session.execute(
            select(VendorImage).where(VendorImage.event_vendor_id == event_vendor_id)
        )
        images = result.scalars().all()
        return [VendorImagesReadSchema(event_vendor_id=image.event_vendor_id, image_data=base64.b64encode(image.image_data).decode('utf-8'), created_at=image.created_at) for image in images] # type: ignore