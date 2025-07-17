# Personal-Firewall-using-Python

A lightweight, CLI-based personal firewall designed for Linux systems. It filters network traffic based on custom rules, detects suspicious behavior in real-time, and takes automatic action to protect your system.

---

🔧 Features

✅ Packet Sniffing using Scapy

📜 Custom Rule Engine for blocking/allowing IPs, ports, and protocols

🚨 Auto-blocker for malicious behavior (flooding, port scans, etc.)

🔒 Kernel-level Blocking using iptables

🧠 Intelligent Alerting every 2 minutes for persistent attackers

🕵‍♂ Real-time Logging of blocked packets

🔄 Live Rule Management (Add, Remove, View rules)

🧹 Unblock Blacklisted IPs via menu

📁 Modular design for easy extensibility


---

🧠 Motivation & AI Use

This project was built as part of my journey into cybersecurity and Python networking.

I used AI (ChatGPT) as a programming assistant—not to replace learning, but to enhance it. It helped me:

Plan a modular architecture

Resolve tricky bugs faster

Add features like auto-blocking & timed alerts

Understand best practices for iptables and Scapy


This allowed me to focus more on how firewalls work at both the user and kernel level while building something functional and secure.


---

🖥 How It Works

The program starts sniffing all incoming packets using Scapy. Every packet is evaluated against:

1. Custom rules defined by the user (IP, port, protocol)


2. Real-time detection of malicious behavior (e.g., too many packets from an IP)



If a packet is flagged:

It's blocked using iptables (kernel level)

Logged with details (IP, port, protocol, reason)

Further packets from that IP are ignored, but an alert is shown every 2 minutes if they keep trying

---

📂 Project Structure

personal-firewall/
├── main.py               # Entry point with menu and sniffer

├── rule_engine.py        # Rule parsing and evaluation

├── auto_blocker.py       # Suspicious behavior detection

├── iptables_wrapper.py   # Kernel-level IP blocking

├── logger.py             # Block log to file

├── rules.json            # Your custom rules


---

🚀 Getting Started

Requirements

Linux (Ubuntu, Kali, etc.)

Python 3.x

scapy, iptables


Installation

git clone https://github.com/Kartik-Bhor/Personal-Firewall-using-Python.git
cd personal-firewall
pip install scapy
sudo python3 main.py


---

📋 Sample Usage

1. Add a Rule – Block specific IP, port or protocol


2. Start Firewall – Begin sniffing and enforcing rules


3. View Logs – See what IPs were blocked and why


4. Unblock – Remove IPs from blacklist when needed


---

🔐 Example Rules (rules.json)

[
  {"action": "block", "ip": "192.168.1.10"},
  {"action": "block", "port": 23},
  {"action": "allow", "protocol": "tcp"}
]

---

💡 Future Improvements

GUI version using Tkinter

E-mail notifications for critical events

Cloud-based rule sync

---

📚 Credits

Built by Kartik Bhor using Python, Linux, and Scapy.
With the support of AI tools for brainstorming and code structure optimization.

