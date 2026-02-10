from fastapi import FastAPI
from app.routers.admin_router import router as admin_router
from app.database import engine, Base
from app.routers.lifecycle_router import router as lifecycle_router

app = FastAPI(title="vpn-observer")

app.include_router(lifecycle_router)

app.include_router(admin_router)


@app.on_event("startup")
def create_tables():
    Base.metadata.create_all(bind=engine)