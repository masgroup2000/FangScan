
FANGSCAN - Ethical Penetration Testing Tool
Advanced penetration testing tool for security professionals, working on both Termux (Android) and Linux systems.
V 2.0

---

## Overview

FangScan v2 is a terminal-based penetration testing tool for Termux and Linux. It performs various scans using Nmap and offers interactive prompts to assist with exploiting detected vulnerabilities.

---
## Differences Between FangScan v1 and v2

### User Interface
- **v1:** Basic Tkinter GUI with fixed layout  
- **v2:** Hybrid terminal + GUI, featuring interactive prompts and colored output  

### Platform Support
- **v1:** Supports Termux and Linux  
- **v2:** Improved support for Termux and Linux with better environment detection and handling  

### Scan Types
- **v1:** Quick, Deep, Web, Vulnerability scans using Nmap scripts  
- **v2:** Same scan types plus interactive exploitation prompts (XSS, SQL Injection, etc.)  

### Vulnerability Detection
- **v1:** Simple regex matching to detect vulnerabilities and suggest actions  
- **v2:** Enhanced CVE detection with interactive prompts to launch real exploit tools  

### Logging
- **v1:** Logs displayed only in GUI console  
- **v2:** Logs saved to timestamped files and displayed in console with colored output  

### Exploit Support
- **v1:** Action buttons that log exploit commands without real execution  
- **v2:** Interactive prompts that ask users to confirm exploit execution and run actual tools  

### Code Structure
- **v1:** Basic object-oriented design with essential comments  
- **v2:** More modular, readable, and well-commented code with improved error handling  

### User Guidance
- **v1:** Simple help pop-up with basic usage info  
- **v2:** Detailed prompts with Yes/No/Maybe options guiding exploit decisions  

### Legal Warnings
- **v1:** Basic warning dialog before starting scans  
- **v2:** Stronger legal disclaimers with explicit confirmation prompts ensuring authorized use
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
