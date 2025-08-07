import os

from fastapi import FastAPI
from routes.user_route import router as user_router
from routes.base_route import router as base_router
from routes.otp_route import router as otp_router
from routes.event_route import router as event_router
from routes.host_route import router as host_router
from fastapi.middleware.cors import CORSMiddleware

allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app = FastAPI() 

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_origin_regex="http://localhost.*",
    allow_credentials=False, # Will need to set to true when we implement authentication
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(user_router)
app.include_router(otp_router)
app.include_router(base_router)
app.include_router(event_router)
app.include_router(host_router)
