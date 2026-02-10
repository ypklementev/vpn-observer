import subprocess
import re


RE_IKE = re.compile(
    r'ikev2-vpn\[(\d+)\]: ESTABLISHED (.+?) ago, .*?\.\.\.(\S+)\[(.*?)\]'
)

RE_EAP = re.compile(r'Remote EAP identity: (\S+)')

RE_CHILD_ID = re.compile(r'ikev2-vpn\{(\d+)\}:')
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

    current_ike = None
    current_child_owner = None   # к какой IKE относится текущий CHILD

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
            current_child_owner = None
            continue

        # --- EAP identity ---
        m = RE_EAP.search(line)
        if m and current_ike:
            sessions[current_ike]["username"] = m.group(1)
            continue

        # --- CHILD header ---
        m = RE_CHILD_ID.search(line)
        if m:
            # CHILD всегда относится к последней IKE
            current_child_owner = current_ike
            continue

        # --- Traffic ---
        if current_child_owner:
            m = RE_BYTES.search(line)
            if m:
                sessions[current_child_owner]["rx"] += int(m.group(1))
                sessions[current_child_owner]["tx"] += int(m.group(2))
                continue

        # --- VPN IP ---
        if current_child_owner:
            m = RE_VPN_IP.search(line)
            if m:
                sessions[current_child_owner]["vpn_ip"] = m.group(1)
                continue

    # --- USERS AGGREGATION ---
    users = {}

    for s in sessions.values():
        u = s["username"]

        if u not in users:
            users[u] = {
                "online": False,
                "rx": 0,
                "tx": 0
            }

        users[u]["online"] = True
        users[u]["rx"] += s["rx"]
        users[u]["tx"] += s["tx"]

    # --- OFFLINE USERS ---
    for u in load_all_users():
        if u not in users:
            users[u] = {
                "online": False,
                "rx": 0,
                "tx": 0
            }

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