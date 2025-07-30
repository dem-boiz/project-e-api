# run_db_setup.py

from database.session import Base, engine
from models import Vendor, Address, HostingInfo, OTPRecord  # Import your new models

# Create tables for all models except OTPRecord
Base.metadata.create_all(bind=engine)
