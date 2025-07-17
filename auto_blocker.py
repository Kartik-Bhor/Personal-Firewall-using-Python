import time
from collections import defaultdict

ip_activity = defaultdict(lambda: {"ports": set(), "timestamps": []})
blacklist = set()

MAX_PACKETS = 100
MAX_PORTS = 5
WINDOW = 10  # seconds

def check_malicious(ip, port):
    now = time.time()
    data = ip_activity[ip]

    # Clean old timestamps
    data["timestamps"] = [t for t in data["timestamps"] if now - t <= WINDOW]
    data["timestamps"].append(now)

    # Track ports
    data["ports"].add(port)

    # Flood detection
    if len(data["timestamps"]) > MAX_PACKETS:
        blacklist.add(ip)
        return True, "Packet Flooding"

    # Port scan detection
    if len(data["ports"]) > MAX_PORTS:
        blacklist.add(ip)
        return True, "Port Scanning"

    return False, ""
