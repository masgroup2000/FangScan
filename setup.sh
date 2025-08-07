#!/bin/bash
# FANGSCAN Installation Script

echo "[+] Installing FANGSCAN dependencies..."

if [ -d "/data/data/com.termux/files/usr" ]; then
    # Termux
    pkg update -y
    pkg install -y python nmap hydra nikto metasploit
else
    # Linux
    sudo apt update
    sudo apt install -y python3 python3-tk nmap hydra nikto metasploit
fi

echo "[+] Setting up FANGSCAN..."
chmod +x fangscan.py

echo "[+] Installation complete!"
echo "Run with: python3 fangscan.py"
