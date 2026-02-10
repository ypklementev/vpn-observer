import subprocess
import re


RE_SESSION = re.compile(
    r'ikev2-vpn\[(\d+)\]: ESTABLISHED (.+?) ago, .*?\.\.\.(\S+)\[(.*?)\]'
)

RE_EAP = re.compile(
    r'Remote EAP identity: (\S+)'
)

RE_CHILD = re.compile(
    r'ikev2-vpn\{(\d+)\}:.*?(\d+) bytes_i.*?(\d+) bytes_o.*?=== (\S+)'
)


def parse_ipsec_status():

    out = subprocess.run(
        ["ipsec", "statusall"],
        capture_output=True,
        text=True
    ).stdout

    lines = out.splitlines()

    sessions = {}
    current_ike = None

    # --------------------
    # PASS 1 — IKE sessions
    # --------------------

    for line in lines:

        m = RE_SESSION.search(line)
        if m:
            ike_id = m.group(1)
            uptime = m.group(2)
            remote_ip = m.group(3)
            bracket_identity = m.group(4)

            sessions[ike_id] = {
                "session_id": ike_id,
                "username": bracket_identity,
                "remote_ip": remote_ip,
                "vpn_ip": "-",
                "uptime": uptime,
                "rx": 0,
                "tx": 0,
                "online": True
            }

            current_ike = ike_id
            continue

        m = RE_EAP.search(line)
        if m and current_ike:
            sessions[current_ike]["username"] = m.group(1)
            continue

    # --------------------
    # PASS 2 — CHILD traffic
    # --------------------

    for line in lines:

        m = RE_CHILD.search(line)
        if not m:
            continue

        child_id = m.group(1)
        rx = int(m.group(2))
        tx = int(m.group(3))
        vpn_ip = m.group(4).split("/")[0]

        # child reqid обычно соответствует ike
        # strongswan выводит child сразу после ike блока
        # поэтому берём последний IKE

        if sessions:
            last_ike = list(sessions.keys())[-1]

            sessions[last_ike]["rx"] += rx
            sessions[last_ike]["tx"] += tx
            sessions[last_ike]["vpn_ip"] = vpn_ip

    # --------------------
    # USERS AGGREGATION
    # --------------------

    users = {}

    for s in sessions.values():
        u = s["username"]

        if u not in users:
            users[u] = {
                "online": True,
                "rx": 0,
                "tx": 0
            }

        users[u]["rx"] += s["rx"]
        users[u]["tx"] += s["tx"]

    # --------------------
    # OFFLINE USERS
    # --------------------

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