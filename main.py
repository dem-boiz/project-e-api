import os

# Initialize logging FIRST before any other imports
from config.logging_config import setup_logging, get_logger
setup_logging()
logger = get_logger("app")

from fastapi import FastAPI
from routes.user_route import router as user_router
from routes.base_route import router as base_router
from routes.otp_route import router as otp_router
from routes.event_route import router as event_router
from routes.host_route import router as host_router
from routes.auth_route import router as auth_router
from fastapi.middleware.cors import CORSMiddleware
from routes.user_event_access_route import router as user_event_access_router
from middleware.request_logging import RequestLoggingMiddleware

logger.info("Starting FastAPI application initialization")

allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app = FastAPI() 

logger.info("FastAPI app instance created")

# Add request logging middleware first
app.add_middleware(RequestLoggingMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_origin_regex="http://localhost.*",
    allow_credentials=True, # Will need to set to true when we implement authentication
    allow_methods=["*"],
    allow_headers=["*"],
)

logger.info("Setting up CORS middleware")

app.include_router(user_router)
app.include_router(otp_router)
app.include_router(base_router)
app.include_router(event_router)
app.include_router(host_router)
app.include_router(auth_router)
app.include_router(user_event_access_router)

logger.info("All routers registered successfully")
logger.info("FastAPI application setup complete")