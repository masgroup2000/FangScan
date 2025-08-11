#!/usr/bin/env python3
# FangScan v2 
import subprocess
import os
import sys
import re

# ANSI color codes for colored output
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
RESET = "\033[0m"

# ASCII art banner lines for FangScan v2
BANNER = [
    "███████╗ █████╗ ███╗   ██╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗",
    "██╔════╝██╔══██╗████╗  ██║██╔════╝     ██╔════╝██╔════╝██╔══██╗████╗  ██║",
    "█████╗  ███████║██╔██╗ ██║██║  ███╗    ███████╗██║     ███████║██╔██╗ ██║",
    "██╔══╝  ██╔══██║██║╚██╗██║██║   ██║    ╚════██║██║     ██╔══██║██║╚██╗██║",
    "██║     ██║  ██║██║ ╚████║╚██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║",
    "╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝",
    "                                                                        "
]

def show_banner():
    # Display the colored ASCII art banner
    for line in BANNER:
        print(f"{CYAN}{line}{RESET}")
    print(f"{YELLOW}FangScan v2 - All-in-one Nmap-based pentesting tool{RESET}\n")

def check_termux():
    # Check for Termux environment by examining environment variables
    prefix = []
    # Termux sets PREFIX to /data/data/com.termux/...
    if 'PREFIX' in os.environ and 'com.termux' in os.environ['PREFIX']:
        print(f"{YELLOW}[!] Termux environment detected. Using termux-chroot for commands.{RESET}")
        print(f"{YELLOW}[!] If tools fail, consider using proot-distro (install Ubuntu/Debian) for better compatibility.{RESET}")
        prefix = ['termux-chroot']
    return prefix

def run_nmap(cmd_args, log_file):
    # Run an Nmap scan with the given arguments and save output to log_file
    print(f"{GREEN}[+] Running: {' '.join(cmd_args)}{RESET}")
    try:
        # Capture output and errors
        result = subprocess.run(cmd_args, capture_output=True, text=True)
        output = result.stdout + result.stderr
    except Exception as e:
        print(f"{RED}[-] Failed to run Nmap: {e}{RESET}")
        return ""
    # Print scan output to terminal
    print(output)
    # Ensure logs directory exists
    if not os.path.isdir('logs'):
        os.makedirs('logs')
    # Write output to log file
    with open(os.path.join('logs', log_file), 'w') as f:
        f.write(output)
    print(f"{GREEN}[+] Output saved to logs/{log_file}{RESET}\n")
    return output

def analyze_output(output, target, prefix):
    # Analyze Nmap output for services and vulnerabilities, and prompt for additional tools
    if not output:
        return
    lines = output.splitlines()
    for line in lines:
        # Check for open ports and services (format: "<port>/tcp open <service>")
        match = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if match:
            port = match.group(1)
            service = match.group(2)
            # If web service detected
            if 'http' in service or port in ['80', '443', '8080']:
                print(f"{YELLOW}[!] Web service detected on port {port} ({service}).{RESET}")
                # Prompt for XSS scanning with dalfox
                ans = input("Run XSS scanner (dalfox) on target? (y/N): ")
                if ans.lower().startswith('y'):
                    url = input("Enter full URL (e.g. https://target) or press Enter for default: ")
                    if not url:
                        url = f"http://{target}"
                    print(f"{GREEN}[+] Running dalfox on {url}{RESET}")
                    subprocess.run(prefix + ['dalfox', 'url', url])
                # Prompt for SQL injection scanning with sqlmap
                ans = input("Run SQL injection scanner (sqlmap) on target? (y/N): ")
                if ans.lower().startswith('y'):
                    url = input("Enter full URL to scan or press Enter for default: ")
                    if not url:
                        url = f"http://{target}"
                    print(f"{GREEN}[+] Running sqlmap on {url}{RESET}")
                    subprocess.run(prefix + ['sqlmap', '-u', url, '--batch'])
            # If SSH service detected
            if service == 'ssh' or port == '22':
                print(f"{YELLOW}[!] SSH service detected on port {port}.{RESET}")
                ans = input("Run Hydra for SSH brute-force? (y/N): ")
                if ans.lower().startswith('y'):
                    user_list = input("Enter path to username list (e.g. users.txt): ")
                    pass_list = input("Enter path to password list (e.g. passwords.txt): ")
                    print(f"{GREEN}[+] Running hydra on ssh://{target}{RESET}")
                    subprocess.run(prefix + ['hydra', '-L', user_list, '-P', pass_list, f'ssh://{target}'])
            # If FTP service detected
            if service == 'ftp' or port == '21':
                print(f"{YELLOW}[!] FTP service detected on port {port}.{RESET}")
                ans = input("Run Hydra for FTP brute-force? (y/N): ")
                if ans.lower().startswith('y'):
                    user_list = input("Enter path to username list (e.g. users.txt): ")
                    pass_list = input("Enter path to password list (e.g. passwords.txt): ")
                    print(f"{GREEN}[+] Running hydra on ftp://{target}{RESET}")
                    subprocess.run(prefix + ['hydra', '-L', user_list, '-P', pass_list, f'ftp://{target}'])
    # Vulnerability check based on output text
    if 'CVE-' in output or 'vuln' in output or 'VULNERABLE' in output:
        print(f"{YELLOW}[!] Potential vulnerabilities or CVEs found in scan output.{RESET}")
        ans = input("Launch Metasploit Framework console? (y/N): ")
        if ans.lower().startswith('y'):
            print(f"{GREEN}[+] Launching msfconsole...{RESET}")
            subprocess.run(prefix + ['msfconsole'])
    if 'RCE' in output or 'command execution' in output.lower():
        print(f"{YELLOW}[!] Possible RCE vulnerability indicated in output.{RESET}")
        ans = input("Launch Metasploit for RCE exploits? (y/N): ")
        if ans.lower().startswith('y'):
            print(f"{GREEN}[+] Launching msfconsole...{RESET}")
            subprocess.run(prefix + ['msfconsole'])

def quick_scan(target, prefix):
    # Perform a quick Nmap scan (fast, common ports)
    cmd = prefix + ['nmap', '-T4', '-F', '-sV', target]
    return run_nmap(cmd, f'quick_scan_{target}.txt')

def deep_scan(target, prefix):
    # Perform a deep Nmap scan (all ports, high speed)
    cmd = prefix + ['nmap', '-p-', '-T4', '--min-rate', '1000', '-sV', target]
    return run_nmap(cmd, f'deep_scan_{target}.txt')

def web_scan(target, prefix):
    # Perform an HTTP-focused Nmap scan (common web ports, HTTP scripts)
    cmd = prefix + ['nmap', '-p', '80,443,8080', '-sV', '--script', 'http-*', target]
    return run_nmap(cmd, f'web_scan_{target}.txt')

def cve_scan(target, prefix):
    # Perform a vulnerability scan using Nmap scripts (vuln and vulners)
    cmd = prefix + ['nmap', '-sV', '--script', 'vuln,vulners', target]
    return run_nmap(cmd, f'cve_scan_{target}.txt')

def export_results(results):
    # Offer to export scan results to plaintext or HTML
    print("Export options:\n1. Plain text report\n2. HTML report")
    choice = input("Choose export format (1 or 2): ")
    if choice == '1':
        filename = 'fangscan_report.txt'
        with open(filename, 'w') as f:
            for mode, content in results.items():
                if content:
                    f.write(f"\n=== {mode.upper()} ===\n")
                    f.write(content + '\n')
        print(f"{GREEN}[+] Plain text report saved to {filename}{RESET}")
    elif choice == '2':
        filename = 'fangscan_report.html'
        with open(filename, 'w') as f:
            f.write("<html><head><title>FangScan Report</title></head><body>")
            f.write("<h1>FangScan v2 Report</h1>")
            for mode, content in results.items():
                if content:
                    f.write(f"<h2>{mode.capitalize()} Scan</h2><pre>{content}</pre>")
            f.write("</body></html>")
        print(f"{GREEN}[+] HTML report saved to {filename}{RESET}")
    else:
        print(f"{RED}[-] Invalid choice, export cancelled.{RESET}")

def main():
    show_banner()
    # Check for Termux environment and get command prefix
    termux_prefix = check_termux()
    # Ask user for the target host or IP
    target = input("Enter target IP or hostname: ")
    # Dictionary to hold scan outputs for export
    results = {
        'quick': None,
        'deep': None,
        'web': None,
        'cve': None
    }
    # Menu loop
    while True:
        print(f"{CYAN}\nAvailable scan modes and options:{RESET}")
        print("1. Quick Scan")
        print("2. Deep Scan")
        print("3. Web Scan")
        print("4. CVE Scan")
        print("5. Brute-Force Detected Services")
        print("6. Export Results")
        print("7. Exit")
        choice = input("Select an option: ")
        if choice == '1':
            results['quick'] = quick_scan(target, termux_prefix)
            analyze_output(results['quick'], target, termux_prefix)
        elif choice == '2':
            results['deep'] = deep_scan(target, termux_prefix)
            analyze_output(results['deep'], target, termux_prefix)
        elif choice == '3':
            results['web'] = web_scan(target, termux_prefix)
            analyze_output(results['web'], target, termux_prefix)
        elif choice == '4':
            results['cve'] = cve_scan(target, termux_prefix)
            analyze_output(results['cve'], target, termux_prefix)
        elif choice == '5':
            # Brute-force option triggers hydra prompts based on scan results
            if any(results.values()):
                combined_output = "\n".join([out for out in results.values() if out])
                analyze_output(combined_output, target, termux_prefix)
            else:
                print(f"{YELLOW}[!] No scan results available. Perform a scan first.{RESET}")
        elif choice == '6':
            export_results(results)
        elif choice == '7':
            print(f"{CYAN}Exiting FangScan. Stay sharp!{RESET}")
            break
        else:
            print(f"{RED}[-] Invalid choice. Please select a valid option.{RESET}")

if __name__ == '__main__':
    main()
