from repository.vendor_images_repository import VendorImagesRepository
import pytest
from fastapi.testclient import TestClient
from main import app
from httpx import AsyncClient, ASGITransport 
from repository import EventVendorsRepository
from database import AsyncSessionLocal
from schema import EventVendorsCreateSchema
from datetime import datetime, date
import uuid
import sys
import asyncio 
from schema.vendor_images_schemas import VendorImagesCreateSchema

@pytest.mark.asyncio
async def test_create_vendor_image():
    async with AsyncSessionLocal() as session: # type: ignore
        repo = VendorImagesRepository(session)
        
        # Test data
        test_event_vendor_id = uuid.UUID('1b8a24d6-62f2-4dc4-b207-acca5d71df7f')
        
        # Read the actual image file
        image_path = r"C:\Users\Simon\Pictures\Bash - Model B.png"
        with open(image_path, "rb") as image_file:
            test_image_data = image_file.read()
        
        vendor_image_data = VendorImagesCreateSchema(
            event_vendor_id=test_event_vendor_id,
            image_data=test_image_data
        )

        # Create new VendorImage
        new_vendor_image = await repo.create_vendor_image(vendor_image_data)
        
        # Assertions
        assert new_vendor_image is not None
        assert new_vendor_image.event_vendor_id == vendor_image_data.event_vendor_id
        assert new_vendor_image.image_data == vendor_image_data.image_data
        assert new_vendor_image.created_at is not None 