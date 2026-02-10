# app/admin.py
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from app.ipsec import parse_ipsec_status

router = APIRouter()

@router.get("/api/realtime")
def realtime():
    return parse_ipsec_status()

@router.get("/admin", response_class=HTMLResponse)
def admin_page():
    with open("app/templates/admin.html") as f:
        return f.read()