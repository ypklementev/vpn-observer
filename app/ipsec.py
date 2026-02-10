# app/ipsec.py
import subprocess
import re


# --- REGEX ---

RE_ESTABLISHED = re.compile(
    r'\[(\d+)\]: ESTABLISHED (\d+) (minute|minutes|hour|hours) ago.*\.\.\.(\d+\.\d+\.\d+\.\d+)'
)

RE_IDENTITY = re.compile(
    r'Remote EAP identity: (\S+)'
)

RE_VPN_IP = re.compile(
    r'=== (\d+\.\d+\.\d+\.\d+)/32'
)

RE_TRAFFIC = re.compile(
    r'(\d+) bytes_i .* (\d+) bytes_o'
)


# --- HELPERS ---

def _uptime_to_seconds(value, unit):
    if "hour" in unit:
        return value * 3600
    return value * 60


def fmt_uptime(sec):
    h = sec // 3600
    m = (sec % 3600) // 60
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


# --- PARSER ---

def parse_ipsec_status():

    output = subprocess.check_output(
        ["ipsec", "statusall"],
        text=True
    )

    sessions = []
    current = None

    for line in output.splitlines():

        # --- NEW SESSION ---
        m = RE_ESTABLISHED.search(line)
        if m:
            if current:
                sessions.append(current)

            sid = int(m.group(1))
            uptime = _uptime_to_seconds(
                int(m.group(2)),
                m.group(3)
            )

            current = {
                "session_id": sid,
                "username": "unknown",
                "remote_ip": m.group(4),
                "vpn_ip": None,
                "uptime_sec": uptime,
                "rx": 0,
                "tx": 0,
                "online": True
            }
            continue

        if not current:
            continue

        # --- USERNAME ---
        m = RE_IDENTITY.search(line)
        if m:
            current["username"] = m.group(1)
            continue

        # --- VPN IP ---
        m = RE_VPN_IP.search(line)
        if m:
            current["vpn_ip"] = m.group(1)
            continue

        # --- TRAFFIC ---
        m = RE_TRAFFIC.search(line)
        if m:
            current["rx"] += int(m.group(1))
            current["tx"] += int(m.group(2))

    if current:
        sessions.append(current)

    # --- агрегируем пользователей ---
    users = {}

    for s in sessions:
        user = s["username"]

        if user not in users:
            users[user] = {
                "online": True,
                "uptime_sec": 0,
                "rx": 0,
                "tx": 0
            }

        users[user]["uptime_sec"] = max(
            users[user]["uptime_sec"],
            s["uptime_sec"]
        )

        users[user]["rx"] += s["rx"]
        users[user]["tx"] += s["tx"]

    # --- offline users ---
    for u in load_all_users():
        if u not in users:
            users[u] = {
                "online": False,
                "uptime_sec": 0,
                "rx": 0,
                "tx": 0
            }

    # --- форматируем uptime ---
    for s in sessions:
        s["uptime"] = fmt_uptime(s["uptime_sec"])

    for u in users.values():
        u["uptime"] = fmt_uptime(u["uptime_sec"])

    return {
        "sessions": sessions,
        "users": users
    }


# --- SECRETS PARSER ---

def load_all_users():
    users = set()

    try:
        with open("/etc/ipsec.secrets") as f:
            for line in f:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                if ": EAP" in line:
                    users.add(line.split(":")[0].strip())

    except Exception:
        pass

    return users