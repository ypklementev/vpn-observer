from collections import defaultdict
import time

HISTORY = defaultdict(list)
MAX_POINTS = 60

def push_snapshot(users):
    ts = int(time.time())

    for user, s in users.items():
        HISTORY[user].append({
            "ts": ts,
            "rx": s.get("rx", 0),
            "tx": s.get("tx", 0),
        })

        if len(HISTORY[user]) > MAX_POINTS:
            HISTORY[user] = HISTORY[user][-MAX_POINTS:]


def get_history():
    return HISTORY