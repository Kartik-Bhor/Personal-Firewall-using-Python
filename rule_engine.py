import json

def load_rules(filename="rules.json"):
    try:
        with open(filename, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return []

def evaluate_packet(packet, rules):
    ip = packet[0].src if hasattr(packet[0], "src") else None
    port = packet[0].sport if hasattr(packet[0], "sport") else None
    proto = packet[0].proto if hasattr(packet[0], "proto") else None

    proto_map = {6: "TCP", 17: "UDP"}
    protocol = proto_map.get(proto, "Unknown")

    for rule in rules:
        if rule["action"] == "block":
            if "ip" in rule and rule["ip"] == ip:
                return "BLOCK", f"Blocked IP: {ip}"
            if "port" in rule and rule["port"] == port:
                return "BLOCK", f"Blocked Port: {port}"
            if "protocol" in rule and rule["protocol"] == protocol:
                return "BLOCK", f"Blocked Protocol: {protocol}"

    return "ALLOW", ""
