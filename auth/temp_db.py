# run_db_setup.py
from database.session import Base, engine
from auth.db_models import OTPRecord

Base.metadata.create_all(bind=engine)
