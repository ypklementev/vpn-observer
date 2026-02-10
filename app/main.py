# app/main.py
from fastapi import FastAPI
from app.admin import router as admin_router

app = FastAPI()
app.include_router(admin_router)