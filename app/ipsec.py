import subprocess
import re


RE_IKE = re.compile(
    r'ikev2-vpn\[(\d+)\]: ESTABLISHED (.+?) ago, .*?\.\.\.([^\[]+)(?:\[(.*?)\])?'
)

RE_EAP = re.compile(
    r'Remote EAP identity: (\S+)'
)

RE_CHILD = re.compile(
    r'ikev2-vpn\{\d+\}:.*?(\d+) bytes_i .*? (\d+) bytes_o.*?=== (\S+)'
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

    for line in lines:
        # --- IKE ---
        m = RE_IKE.search(line)
        if m:
            ike_id = m.group(1)
            
            sessions[ike_id] = {
                "session_id": ike_id,
                "username": None,  # Изначально не устанавливаем
                "remote_ip": m.group(3),
                "vpn_ip": "-",
                "uptime": m.group(2),
                "rx": 0,
                "tx": 0,
                "online": True
            }
            
            current_ike = ike_id
            continue

        # --- EAP identity ---
        m = RE_EAP.search(line)
        if m and current_ike:
            sessions[current_ike]["username"] = m.group(1)
            continue

        # --- CHILD (traffic + VPN IP) ---
        m = RE_CHILD.search(line)
        if m and current_ike:
            sessions[current_ike]["rx"] += int(m.group(1))
            sessions[current_ike]["tx"] += int(m.group(2))
            sessions[current_ike]["vpn_ip"] = m.group(3).split("/")[0]
            
            # Если username еще не установлен через EAP, используем то, что в квадратных скобках
            if sessions[current_ike]["username"] is None:
                # Пытаемся извлечь из предыдущих строк или оставляем как есть
                sessions[current_ike]["username"] = "unknown"
            continue

    # Удаляем сессии без username (если такие есть)
    sessions = {k: v for k, v in sessions.items() if v["username"] is not None}
    
    # --- USERS AGGREGATION ---
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