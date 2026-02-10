from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.dialects.postgresql import INET

from app.database import Base


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    unique_id = Column(String, unique=True, nullable=False)
    username = Column(String, nullable=False)
    connected_at = Column(DateTime, nullable=False)
    disconnected_at = Column(DateTime, nullable=True)
    assigned_ip = Column(INET, nullable=False)
    remote_ip = Column(INET, nullable=False)