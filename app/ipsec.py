# app/ipsec.py
import subprocess
import re

SESSION_RE = re.compile(
    r'^\s*(?P<name>\S+)\[(?P<id>\d+)\]:\s+ESTABLISHED.*?,\s+(?P<uptime>[\w\s]+)',
    re.MULTILINE
)

CHILD_RE = re.compile(
    r'^\s+installed.*?SPIs.*?in\s+(?P<rx>\d+)\s+bytes,\s+out\s+(?P<tx>\d+)\s+bytes',
    re.MULTILINE
)

def parse_ipsec_status():
    proc = subprocess.run(
        ["ipsec", "statusall"],
        capture_output=True,
        text=True
    )
    text = proc.stdout

    users = {}

    sessions = SESSION_RE.finditer(text)
    children = CHILD_RE.finditer(text)

    child_list = list(children)
    child_idx = 0

    for s in sessions:
        rx = tx = 0
        if child_idx < len(child_list):
            rx = int(child_list[child_idx].group("rx"))
            tx = int(child_list[child_idx].group("tx"))
            child_idx += 1

        users[s.group("name")] = {
            "online": True,
            "uptime": s.group("uptime"),
            "rx": rx,
            "tx": tx
        }

    return users