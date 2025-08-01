from fastapi import APIRouter

router = APIRouter()

@router.get("/", tags=["base"])
async def read_root():
    return {"message": "Welcome to Project E API"}