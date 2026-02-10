from datetime import datetime, timezone


def utc_now() -> datetime:
    """
    Returns timezone-aware UTC datetime.

    Always use this function instead of datetime.utcnow()
    to avoid naive datetime bugs.
    """
    return datetime.now(timezone.utc)