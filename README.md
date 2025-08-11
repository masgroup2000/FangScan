
FANGSCAN - Ethical Penetration Testing Tool
Advanced penetration testing tool for security professionals, working on both Termux (Android) and Linux systems.
V 2.0

---

## Overview

FangScan v2 is a terminal-based penetration testing tool for Termux and Linux. It performs various scans using Nmap and offers interactive prompts to assist with exploiting detected vulnerabilities.

---

## Features

- Quick, Deep, Web, and Vulnerability scans using Nmap scripts  
- Interactive exploitation prompts (XSS, SQL Injection, EternalBlue, Log4Shell)  
- Logs saved with timestamps in `logs/` directory  
- Supports Linux and Termux (Android) environments  
- Clear legal disclaimers before use  

---

## Requirements

- Python 3.x  
- Nmap  
- Nikto  
- Hydra  
- SQLMap  
- Metasploit Framework  
- Dalfox  
- XSser  

---

## Installation

### Step 1: Clone the repository

```bash
git clone https://github.com/masgroup2000/FangScan.git
cd FangScan

```
Step 2: Run the installation script (Linux or Termux)
```bash
bash install.sh
```
This installs all necessary dependencies automatically.

---
#Usage

Make the main script executable:
```bash
chmod +x fangscan_v3.py
```
Run the tool:
```
./fangscan_v3.py
# or
python3 fangscan_v3.py
```
Follow the prompts to enter the target, select scan types, and decide on exploitation options.
