#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, UDP
import datetime, time, json
from rule_engine import load_rules, evaluate_packet
from auto_blocker import check_malicious, blacklist
from logger import log_blocked_packet
from iptables_wrapper import block_ip, unblock_ip

RULES_FILE = "rules.json"
ALERT_INTERVAL = 120  # seconds
alerted_ips_timestamps = {}  # For alerting blocked IPs every 2 mins

# ------------------- Rule Management -------------------

def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)

def list_rules():
    rules = load_rules()
    print("\n📜 Current Rules:")
    for i, rule in enumerate(rules):
        print(f"{i+1}. {rule}")
    print()

def add_rule():
    action = input("Action (block/allow): ").strip().lower()
    target = input("Target (ip/port/protocol): ").strip().lower()
    value = input("Value: ").strip()

    if target == "port":
        try:
            value = int(value)
        except:
            print("❌ Invalid port number.")
            return

    rule = {"action": action, target: value}
    rules = load_rules()
    rules.append(rule)
    save_rules(rules)
    print("✅ Rule added.\n")

def remove_rule():
    rules = load_rules()
    list_rules()
    try:
        index = int(input("Enter rule number to remove: ")) - 1
        if 0 <= index < len(rules):
            removed = rules.pop(index)
            save_rules(rules)
            print(f"🗑 Removed rule: {removed}\n")
        else:
            print("❌ Invalid number.\n")
    except ValueError:
        print("❌ Enter a valid number.\n")

def show_blacklisted_ips():
    print("\n🚫 Blacklisted IPs:")
    if not blacklist:
        print("No IPs have been auto-blocked yet.")
    else:
        for i, ip in enumerate(blacklist):
            print(f"{i+1}. {ip}")
    print()

def unblock_blacklisted_ip():
    if not blacklist:
        print("\nℹ No IPs to unblock.\n")
        return
    show_blacklisted_ips()
    try:
        index = int(input("Enter number of IP to unblock: ")) - 1
        ip_list = list(blacklist)
        if 0 <= index < len(ip_list):
            ip = ip_list[index]
            unblock_ip(ip)
            blacklist.remove(ip)
            print(f"✅ Unblocked IP: {ip}\n")
        else:
            print("❌ Invalid selection.\n")
    except ValueError:
        print("❌ Please enter a valid number.\n")

# ------------------- Packet Processing -------------------

def packet_callback(packet):
    rules = load_rules()
    time_stamp = datetime.datetime.now().strftime("%H:%M:%S")

    if IP in packet:
        ip_layer = packet[IP]
        proto = "Unknown"
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        port = packet.dport if hasattr(packet, 'dport') else "-"

        # If already blocked, don't sniff — alert only every 2 mins
        if src_ip in blacklist:
            current_time = time.time()
            last_alert = alerted_ips_timestamps.get(src_ip, 0)
            if current_time - last_alert >= ALERT_INTERVAL:
                print(f"[{time_stamp}] ⚠ ALERT | Blocked IP {src_ip} is still sending packets!")
                alerted_ips_timestamps[src_ip] = current_time
            return

        # Static rule evaluation
        verdict, reason = evaluate_packet(packet, rules)

        # Auto-blocker check
        malicious, mal_reason = check_malicious(src_ip, port)
        if malicious:
            verdict = "BLOCK"
            reason = f"Auto-blocked: {mal_reason}"
            block_ip(src_ip)
            blacklist.add(src_ip)
            alerted_ips_timestamps[src_ip] = time.time()

        if verdict == "BLOCK":
            print(f"[{time_stamp}] ❌ BLOCKED | {proto} | {src_ip} → {dst_ip} | {reason}")
            log_blocked_packet(src_ip, dst_ip, proto, port, reason)
        else:
            print(f"[{time_stamp}] ✅ ALLOWED | {proto} | {src_ip} → {dst_ip}")

# ------------------- Menu -------------------

def start_menu():
    while True:
        print("\n🛡 Personal Firewall Main Menu")
        print("1. Start Firewall")
        print("2. List Rules")
        print("3. Add Rule")
        print("4. Remove Rule")
        print("5. View Blacklisted IPs")
        print("6. Unblock Blacklisted IP")
        print("7. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            print("🚨 Starting firewall... Press Ctrl+C to stop.\n")
            sniff(prn=packet_callback, store=False)
        elif choice == "2":
            list_rules()
        elif choice == "3":
            add_rule()
        elif choice == "4":
            remove_rule()
        elif choice == "5":
            show_blacklisted_ips()
        elif choice == "6":
            unblock_blacklisted_ip()
        elif choice == "7":
            print("👋 Exiting.")
            break
        else:
            print("❌ Invalid option.")

if __name__ == "__main__":
    start_menu()
