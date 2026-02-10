from collections import defaultdict
import time

HISTORY = defaultdict(list)
PREV = {}  # user -> {rx, tx, ts}

MAX_POINTS = 60


def push_snapshot(users):
    now = time.time()

    for user, s in users.items():

        rx = s.get("rx", 0)
        tx = s.get("tx", 0)

        if user in PREV:
            prev = PREV[user]

            dt = now - prev["ts"]
            if dt <= 0:
                continue

            speed_rx = max(0, (rx - prev["rx"]) / dt)
            speed_tx = max(0, (tx - prev["tx"]) / dt)

        else:
            speed_rx = 0
            speed_tx = 0

        HISTORY[user].append({
            "ts": int(now),
            "rx": speed_rx,
            "tx": speed_tx
        })

        if len(HISTORY[user]) > MAX_POINTS:
            HISTORY[user] = HISTORY[user][-MAX_POINTS:]

        PREV[user] = {
            "rx": rx,
            "tx": tx,
            "ts": now
        }


def get_history():
    return HISTORY