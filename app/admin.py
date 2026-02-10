# app/admin.py
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from app.history import push_snapshot, get_history
from app.ipsec import parse_ipsec_status

router = APIRouter()

@router.get("/api/realtime")
def realtime():
    data = parse_ipsec_status()
    push_snapshot(data["users"])
    return data

@router.get("/api/history")
def history():
    return get_history()

@router.get("/admin", response_class=HTMLResponse)
def admin_page():
    with open("app/templates/admin.html") as f:
        return f.read()