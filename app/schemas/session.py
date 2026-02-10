from pydantic import BaseModel
from datetime import datetime


class LifecycleEvent(BaseModel):
    event: str
    unique_id: str
    username: str
    assigned_ip: str
    remote_ip: str


class SessionResponse(BaseModel):
    unique_id: str
    username: str
    connected_at: datetime
    disconnected_at: datetime | None
    assigned_ip: str
    remote_ip: str