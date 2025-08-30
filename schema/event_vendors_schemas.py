from pydantic import BaseModel, EmailStr
from uuid import UUID
from datetime import datetime
from typing import Optional

class EventVendorsCreateSchema(BaseModel):
    event_id: UUID
    user_id: UUID
    event_date: datetime

class EventVendorsReadSchema(BaseModel):
    event_id: UUID
    user_id: UUID
    event_date: datetime
    added_at: datetime
    