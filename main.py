from fastapi import FastAPI
from routes.user_route import router as user_router
from routes.base_route import router as base_router
from routes.otp_route import router as otp_router
from routes.event_route import router as event_router
import os


app = FastAPI() 

# Debug endpoint to test database connection
@app.get("/debug/db-test")
async def test_db_connection():
    try:
        from database.session import get_async_session
        from sqlalchemy import text
        
        async for session in get_async_session():
            result = await session.execute(text("SELECT 1 as test"))
            test_value = result.scalar()
            return {"status": "success", "test_query": test_value, "database_url": os.getenv("DATABASE_URL", "NOT_SET")[:50] + "..."}
    except Exception as e:
        return {"status": "error", "error": str(e), "database_url": os.getenv("DATABASE_URL", "NOT_SET")[:50] + "..."}

app.include_router(user_router)
app.include_router(otp_router)
app.include_router(base_router)
app.include_router(event_router)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)