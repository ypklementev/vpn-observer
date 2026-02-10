from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.schemas.session import LifecycleEvent
from app.services.session_service import SessionService

router = APIRouter(prefix="/lifecycle")


@router.post("/event")
def lifecycle_event(event: LifecycleEvent, db: Session = Depends(get_db)):
    try:
        return SessionService.handle_event(db, event)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))