from fastapi import FastAPI
from app.routers.lifecycle_router import router as lifecycle_router

app = FastAPI(title="vpn-observer")

app.include_router(lifecycle_router)