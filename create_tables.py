import asyncio
import sys
import os

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database.session import engine, Base
# Import all models that might be needed for foreign key dependencies
from models.user_grant import UserGrant
from models.device_grant import DeviceGrant
from models.invite import Invite
from models.user import User
from models.event import Event
from models.guest_device import GuestDevice

async def create_tables():
    print("Creating/updating specific database tables...")
    
    # Define tables to update - focus on these two but include dependencies
    update_tables = [UserGrant.__table__, DeviceGrant.__table__]
    
    # Create or update just these tables
    async with engine.begin() as conn:
        # Create all tables in case foreign key tables don't exist
        await conn.run_sync(Base.metadata.create_all)
        
        # Now recreate just the specific tables we want to update
        print("Recreating specific tables...")
        # Drop tables if they exist to ensure schema is updated
        await conn.run_sync(Base.metadata.drop_all, tables=update_tables)
        # Create tables
        await conn.run_sync(Base.metadata.create_all, tables=update_tables)
    
    print("Tables 'user_grants' and 'device_grants' created/updated successfully!")

if __name__ == "__main__":
    asyncio.run(create_tables())
