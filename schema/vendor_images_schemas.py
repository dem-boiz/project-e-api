from pydantic import BaseModel, EmailStr
from uuid import UUID
from datetime import datetime
from typing import List, Optional

class VendorImagesCreateSchema(BaseModel):
    event_vendor_id: str
    image_data: str  # Base64 encoded string

class VendorImagesReadSchema(BaseModel):
    event_vendor_id: UUID
    image_data: str
    created_at: datetime

class VendorImagesDeleteSchema(BaseModel):
    event_vendor_id: Optional[UUID] = None
    image_id: Optional[UUID] = None