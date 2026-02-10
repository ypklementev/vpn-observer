from sqlalchemy.orm import Session
from app.repositories.session_repository import SessionRepository


class SessionService:

    @staticmethod
    def handle_event(db: Session, event):
        if event.event == "up-client":
            return SessionRepository.create_session(
                db=db,
                unique_id=event.unique_id,
                username=event.username,
                assigned_ip=event.assigned_ip,
                remote_ip=event.remote_ip
            )

        elif event.event == "down-client":
            return SessionRepository.close_session(
                db=db,
                unique_id=event.unique_id
            )

        else:
            raise ValueError("Unknown event type")