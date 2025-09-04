from pydantic import BaseModel, EmailStr
from uuid import UUID
from datetime import datetime
from typing import List, Optional

class EventVendorsCreateSchema(BaseModel):
    event_id: UUID
    user_id: UUID

class EventVendorsReadSchema(BaseModel):
    event_id: UUID
    user_id: UUID
    added_at: datetime
    
class EventVendorsUpdateSchema(BaseModel):
    event_id: Optional[UUID] = None
    user_id: UUID
    vendor_description: Optional[str] = None
    vendor_images: Optional[List[bytes]] = None

class EventVendorSearchSchema(BaseModel):
    user_id: Optional[UUID] = None
    event_id: Optional[UUID] = None
