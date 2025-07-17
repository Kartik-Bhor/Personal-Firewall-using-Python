# iptables_wrapper.py — system-level block/unblock using iptables

import subprocess

def block_ip(ip):
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"🚫 [iptables] IP {ip} has been blocked.")
    except Exception as e:
        print(f"[iptables] Failed to block IP {ip}: {e}")

def unblock_ip(ip):
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"🔓 [iptables] IP {ip} has been unblocked.")
    except Exception as e:
        print(f"[iptables] Failed to unblock IP {ip}: {e}")
