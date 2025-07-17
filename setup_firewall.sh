#!/bin/bash

echo "🔧 Setting up Personal Firewall project..."

# Create logs directory
if [ ! -d "logs" ]; then
  mkdir logs
  echo "📁 Created logs/ directory"
fi

# Create rules.json if not exists
if [ ! -f "rules.json" ]; then
  echo '[
  {
    "action": "block",
    "ip": "192.168.1.100"
  },
  {
    "action": "block",
    "port": 23
  },
  {
    "action": "block",
    "protocol": "UDP"
  }
]' > rules.json
  echo "🧾 Created default rules.json"
fi

# Install scapy if not present
if ! python3 -c "import scapy.all" &>/dev/null; then
  echo "📦 Installing scapy..."
  pip3 install scapy
else
  echo "✅ Scapy already installed"
fi

# Ask for sudo access for iptables
echo "🔐 Checking sudo access for iptables..."
sudo echo "sudo access confirmed"

echo "✅ Setup complete. Run the firewall using:"
echo "   python3 main.py"
