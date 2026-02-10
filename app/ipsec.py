import subprocess
import re
import time

PREV_USERS = {}
HISTORY = {}

RE_IKE = re.compile(
    r'ikev2-vpn\[(\d+)\]: ESTABLISHED (.+?) ago, .*?\.\.\.(\S+)\[(.*?)\]'
)

RE_EAP = re.compile(r'Remote EAP identity: (\S+)')

RE_CHILD_REQID = re.compile(r'ikev2-vpn\{\d+\}:.*?reqid (\d+)')
RE_BYTES = re.compile(r'(\d+) bytes_i .*? (\d+) bytes_o')
RE_VPN_IP = re.compile(r'=== (\d+\.\d+\.\d+\.\d+)/\d+')


def parse_ipsec_status():

    out = subprocess.run(
        ["ipsec", "statusall"],
        capture_output=True,
        text=True
    ).stdout

    lines = out.splitlines()

    sessions = {}
    reqid_to_ike = {}

    current_ike = None
    current_reqid = None

    for line in lines:

        # --- IKE ---
        m = RE_IKE.search(line)
        if m:
            ike_id = m.group(1)

            sessions[ike_id] = {
                "session_id": ike_id,
                "username": m.group(4),
                "remote_ip": m.group(3),
                "vpn_ip": "-",
                "uptime": m.group(2),
                "rx": 0,
                "tx": 0,
                "online": True
            }

            current_ike = ike_id
            continue

        # --- EAP ---
        m = RE_EAP.search(line)
        if m and current_ike:
            sessions[current_ike]["username"] = m.group(1)
            continue

        # --- CHILD reqid ---
        m = RE_CHILD_REQID.search(line)
        if m and current_ike:
            current_reqid = m.group(1)
            reqid_to_ike[current_reqid] = current_ike
            continue

        # --- Traffic ---
        m = RE_BYTES.search(line)
        if m and current_reqid in reqid_to_ike:
            ike = reqid_to_ike[current_reqid]
            sessions[ike]["rx"] += int(m.group(1))
            sessions[ike]["tx"] += int(m.group(2))
            continue

        # --- VPN IP ---
        m = RE_VPN_IP.search(line)
        if m and current_reqid in reqid_to_ike:
            ike = reqid_to_ike[current_reqid]
            sessions[ike]["vpn_ip"] = m.group(1)
            continue

    # --- USERS AGGREGATION ---
    users = {}

    for s in sessions.values():
        u = s["username"]

        if u not in users:
            users[u] = {"online": False, "rx": 0, "tx": 0}

        users[u]["online"] = True
        users[u]["rx"] += s["rx"]
        users[u]["tx"] += s["tx"]

    # --- OFFLINE USERS ---
    for u in load_all_users():
        if u not in users:
            users[u] = {
                "online": False,
                "rx": 0,
                "tx": 0,
                "speed_rx": 0,
                "speed_tx": 0
            }

    # ✅ ВОТ ЭТО БЫЛО ПРОПУЩЕНО
    calculate_speed(users)

    return {
        "sessions": list(sessions.values()),
        "users": users
    }


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

def calculate_speed(users):

    global PREV_USERS, HISTORY

    now = time.time()

    for username, u in users.items():

        if username in PREV_USERS:

            prev = PREV_USERS[username]
            dt = now - prev["time"]

            if dt > 0:
                u["speed_rx"] = max(0, (u["rx"] - prev["rx"]) / dt)
                u["speed_tx"] = max(0, (u["tx"] - prev["tx"]) / dt)
            else:
                u["speed_rx"] = 0
                u["speed_tx"] = 0

        else:
            u["speed_rx"] = 0
            u["speed_tx"] = 0

        # --- history ---
        HISTORY.setdefault(username, [])
        HISTORY[username].append({
            "rx": u["speed_rx"],
            "tx": u["speed_tx"]
        })

        HISTORY[username] = HISTORY[username][-60:]

    PREV_USERS = {
        u: {
            "rx": users[u]["rx"],
            "tx": users[u]["tx"],
            "time": now
        }
        for u in users
    }