from fastapi import APIRouter

router = APIRouter()

@router.get("/", tags=["base"])
async def read_root():
    return {"message": "Welcome to Project E API"}

@router.get("/health", tags=["base"])
async def health_check():
    return {"status": "healthy", "message": "API is running"}

@router.get("/debug", tags=["base"])
async def debug_info():
    import os
    return {
        "environment": "production" if os.getenv("RAILWAY_ENVIRONMENT") else "development",
        "port": os.getenv("PORT", "not set"),
        "database_configured": bool(os.getenv("DATABASE_URL"))
    }