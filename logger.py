import os
from datetime import datetime

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "firewall_log.txt")

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

def log_blocked_packet(src_ip, dst_ip, proto, port, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] BLOCKED | {proto} | {src_ip} --> {dst_ip} | Port: {port} | Reason: {reason}\n"

    with open(LOG_FILE, "a") as f:
        f.write(log_line)
