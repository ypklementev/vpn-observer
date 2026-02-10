# app/ipsec.py
import subprocess
import re


RE_ESTABLISHED = re.compile(
    r'\[(\d+)\]: ESTABLISHED (\d+) (minutes?|hours?) ago'
)

RE_IDENTITY = re.compile(
    r'Remote EAP identity: (\S+)'
)

RE_TRAFFIC = re.compile(
    r'(\d+) bytes_i .* (\d+) bytes_o'
)


def parse_ipsec_status():
    proc = subprocess.run(
        ["ipsec", "statusall"],
        capture_output=True,
        text=True
    )

    lines = proc.stdout.splitlines()

    sessions = {}
    current_ike = None

    for line in lines:

        # --- ESTABLISHED ---
        m = RE_ESTABLISHED.search(line)
        if m:
            ike_id = m.group(1)
            uptime = f"{m.group(2)} {m.group(3)}"

            sessions[ike_id] = {
                "username": "unknown",
                "uptime": uptime,
                "rx": 0,
                "tx": 0,
                "online": True
            }
            current_ike = ike_id
            continue

        # --- USERNAME ---
        m = RE_IDENTITY.search(line)
        if m and current_ike:
            sessions[current_ike]["username"] = m.group(1)
            continue

        # --- TRAFFIC ---
        m = RE_TRAFFIC.search(line)
        if m and current_ike:
            sessions[current_ike]["rx"] += int(m.group(1))
            sessions[current_ike]["tx"] += int(m.group(2))
            continue

    # --- агрегируем по пользователю ---
    users = {}

    for s in sessions.values():
        user = s["username"]

        if user not in users:
            users[user] = {
                "online": True,
                "uptime": s["uptime"],
                "rx": 0,
                "tx": 0
            }

        users[user]["rx"] += s["rx"]
        users[user]["tx"] += s["tx"]

    # --- добавляем offline пользователей ---
    all_users = load_all_users()

    for u in all_users:
        if u not in users:
            users[u] = {
                "online": False,
                "uptime": "-",
                "rx": 0,
                "tx": 0
            }

    return users

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