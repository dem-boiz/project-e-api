from pydantic import BaseModel, EmailStr
from uuid import UUID
from datetime import datetime
from typing import List, Optional

class EventVendorsCreateSchema(BaseModel):
    event_id: UUID
    user_id: UUID
    event_date: datetime

class EventVendorsReadSchema(BaseModel):
    event_id: UUID
    user_id: UUID
    event_date: datetime
    added_at: datetime
    
class EventVendorsUpdateSchema(BaseModel):
    event_id: Optional[UUID] = None
    user_id: UUID
    vendor_description: Optional[str] = None
    vendor_images: Optional[List[bytes]] = None