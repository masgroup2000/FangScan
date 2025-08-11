---

## installation script v2

```bash
#!/bin/bash

echo "Starting FangScan v2 dependency installation..."

if command -v apt >/dev/null 2>&1; then
    echo "Detected Debian/Ubuntu Linux"
    sudo apt update
    sudo apt install -y python3 python3-pip nmap nikto hydra sqlmap metasploit-framework dalfox xsser
elif command -v pkg >/dev/null 2>&1; then
    echo "Detected Termux (Android)"
    pkg update
    pkg install -y python nmap nikto hydra sqlmap metasploit dalfox xsser
else
    echo "Unsupported package manager. Please install dependencies manually."
    exit 1
fi

echo "Installation complete! You can now run fangscan.py"
