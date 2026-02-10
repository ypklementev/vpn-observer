from pydantic import BaseModel
from typing import Optional
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
    disconnected_at: Optional[datetime]
    assigned_ip: str
    remote_ip: str

    class Config:
        orm_mode = True