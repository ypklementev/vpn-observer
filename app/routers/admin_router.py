# app/routers/admin_router.py
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.dependencies import get_db
from app.models.session import Session as SessionModel

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/admin", response_class=HTMLResponse)
def admin_users(request: Request, db: Session = Depends(get_db)):
    users = (
        db.query(
            SessionModel.username,
            func.count(SessionModel.id).label("sessions"),
            func.max(SessionModel.connected_at).label("last_seen"),
            func.bool_or(SessionModel.disconnected_at.is_(None)).label("online"),
        )
        .group_by(SessionModel.username)
        .all()
    )

    return templates.TemplateResponse(
        "users.html",
        {"request": request, "users": users},
    )


@router.get("/admin/user/{username}", response_class=HTMLResponse)
def admin_user_sessions(username: str, request: Request, db: Session = Depends(get_db)):
    sessions = (
        db.query(SessionModel)
        .filter(SessionModel.username == username)
        .order_by(SessionModel.connected_at.desc())
        .all()
    )

    return templates.TemplateResponse(
        "sessions.html",
        {"request": request, "username": username, "sessions": sessions},
    )