from collections import defaultdict, deque
import time

MAX_POINTS = 60  # 5 минут если refresh 5 сек

history = defaultdict(lambda: deque(maxlen=MAX_POINTS))


def push_snapshot(data):
    ts = int(time.time())

    for user, s in data.items():
        history[user].append({
            "ts": ts,
            "rx": s["rx"],
            "tx": s["tx"]
        })


def get_history():
    return history