from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
import uuid
from config.logging_config import get_logger
from handlers import create_event_vendor_handler, update_event_vendors_handler, delete_event_vendors_handler, get_vendors_for_event_handler, get_event_vendor_record_handler, get_events_for_vendor_handler, delete_vendors_for_event_handler, delete_vendor_from_events_handler
from database.session import get_async_session
from handlers.event_vendor_handler import delete_vendors_for_event_handler
from routes.event_vendors_route import get_event_vendor_service
from services import EventVendorsService
from models import User
from schema import EventVendorsReadSchema, EventVendorSearchSchema, EventVendorsCreateSchema, EventVendorsUpdateSchema
from services.auth_service import (
    get_current_user,
    validate_token_parent_session,
)

router = APIRouter(prefix="/event-vendors", tags=["event-vendors"])

# Initialize logger
logger = get_logger("api.event-vendors")

async def verify_event_vendor_ownership(
    data: EventVendorSearchSchema = Depends(),
    current_user: User = Depends(get_current_user),
    service: EventVendorsService = Depends(get_event_vendor_service)
) -> tuple[uuid.UUID, User]:
    """Verify that the authenticated user owns the event"""
    try:
        event_id = data.event_id
        # Check verification for Vendor ownership of the event vendor record
        logger.info(f"Verifying ownership for event vendor with event ID '{event_id}' and user ID '{current_user.id}'")
        event_vendor_search = EventVendorSearchSchema(user_id=current_user.id, event_id=event_id)
        event_vendor_record = await service.get_event_vendor_record_service(event_vendor_search)
        if not event_vendor_record or event_vendor_record.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only manage event vendors that you own"
            ) 
        return event_id, current_user # type: ignore
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid event ID format"
        )
    except Exception as e:
        raise HTTPException(
            status_code=getattr(e, 'status_code', status.HTTP_404_NOT_FOUND),
            detail=f"Error occured. {e}"
        )


# Dependency to get EventVendor
async def get_event_vendor_service(session: AsyncSession = Depends(get_async_session))-> EventVendorsService:
    return EventVendorsService(session) 

@router.post("/",
              response_model=EventVendorsReadSchema, 
              status_code=status.HTTP_201_CREATED 
)
async def create_event_vendor(
    data: EventVendorsCreateSchema,
    service: EventVendorsService = Depends(get_event_vendor_service)
):
    return await create_event_vendor_handler(data=data, service=service)
    
@router.get("/", response_model=EventVendorsReadSchema, status_code=status.HTTP_302_FOUND)
async def get_event_vendor(
    data: EventVendorSearchSchema = Depends(),
    service: EventVendorsService = Depends(get_event_vendor_service)
):
    return await get_event_vendor_record_handler(data=data, service=service)

@router.get("/user-id", response_model=List[EventVendorsReadSchema], status_code=status.HTTP_302_FOUND)
async def get_events_for_vendor(
    data: EventVendorSearchSchema = Depends(),
    service: EventVendorsService = Depends(get_event_vendor_service)
):
    return await get_events_for_vendor_handler(data=data, service=service)

@router.get("/event-id", response_model=List[EventVendorsReadSchema], status_code=status.HTTP_302_FOUND)
async def get_vendors_for_event(
    data: EventVendorSearchSchema = Depends(),
    service: EventVendorsService = Depends(get_event_vendor_service)
):
    return await get_vendors_for_event_handler(data=data, service=service)


@router.patch("/", 
              response_model=EventVendorsReadSchema, 
              status_code=status.HTTP_202_ACCEPTED,
              dependencies=[
        Depends(validate_token_parent_session),
        Depends(verify_event_vendor_ownership)
    ])
async def update_user(
    data: EventVendorsUpdateSchema = Depends(), 
    service: EventVendorsService = Depends(get_event_vendor_service),
    
):
    return await update_event_vendors_handler(data=data, service=service)


@router.delete("/", status_code=status.HTTP_204_NO_CONTENT)
async def delete_event_vendor(
    data: EventVendorSearchSchema = Depends(),
    service: EventVendorsService = Depends(get_event_vendor_service)
):
    return await delete_event_vendors_handler(data=data, service=service)

@router.delete("/event-id", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vendors_for_event(
    data: EventVendorSearchSchema = Depends(),
    service: EventVendorsService = Depends(get_event_vendor_service)
):
    return await delete_vendors_for_event_handler(data=data, service=service)

@router.delete("/single", status_code=status.HTTP_204_NO_CONTENT)
async def delete_single_event_vendor(
    data: EventVendorSearchSchema = Depends(),
    service: EventVendorsService = Depends(get_event_vendor_service)
):
    return await delete_vendors_for_event(data=data, service=service)