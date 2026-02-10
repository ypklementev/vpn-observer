from sqlalchemy.orm import Session
from datetime import datetime

from app.models.session import Session as SessionModel


class SessionRepository:

    @staticmethod
    def create_session(
        db: Session,
        unique_id: str,
        username: str,
        assigned_ip: str,
        remote_ip: str
    ):
        session = SessionModel(
            unique_id=unique_id,
            username=username,
            connected_at=datetime.utcnow(),
            assigned_ip=assigned_ip,
            remote_ip=remote_ip
        )

        db.add(session)
        db.commit()
        db.refresh(session)

        return session

    @staticmethod
    def close_session(db: Session, unique_id: str):
        session = db.query(SessionModel).filter_by(unique_id=unique_id).first()

        if session:
            session.disconnected_at = datetime.utcnow()
            db.commit()

        return session