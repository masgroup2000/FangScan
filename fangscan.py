#!/usr/bin/env python3
#Fangscan v2
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

# ASCII art banner lines for FangScan v3
BANNER = [
    "        ███████╗ █████╗ ███╗   ██╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗████╗  ██║██╔════╝     ██╔════╝██╔════╝██╔══██╗████╗  ██║
█████╗  ███████║██╔██╗ ██║██║  ███╗    ███████╗██║     ███████║██╔██╗ ██║
██╔══╝  ██╔══██║██║╚██╗██║██║   ██║    ╚════██║██║     ██╔══██║██║╚██╗██║
██║     ██║  ██║██║ ╚████║╚██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                                                       ",
    "            v2 - Terminal Pentesting Tool              "
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
            f.write("<h1>FangScan v3 Report</h1>")
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
    main()███████╗ █████╗ ███╗   ██╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗████╗  ██║██╔════╝     ██╔════╝██╔════╝██╔══██╗████╗  ██║
█████╗  ███████║██╔██╗ ██║██║  ███╗    ███████╗██║     ███████║██╔██╗ ██║
██╔══╝  ██╔══██║██║╚██╗██║██║   ██║    ╚════██║██║     ██╔══██║██║╚██╗██║
██║     ██║  ██║██║ ╚████║╚██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""
        subtitle = "Web Penetration Testing Tool by MG"

        # Header
        header = ttk.Frame(self.root)
        header.pack(fill=tk.X, pady=(10, 0))

        tk.Label(header, text=ascii_art, font=("Courier", 8),
                fg=self.fang_red, bg=self.fang_black, justify="center").pack(pady=(0, 5))
        tk.Label(header, text=subtitle, font=("Helvetica", 10),
                fg="white", bg=self.fang_black).pack(pady=(0, 10))

        # Target Input
        target_frame = ttk.Frame(self.root)
        ttk.Label(target_frame, text="TARGET:").grid(row=0, column=0, sticky="w")
        self.entry_target = ttk.Entry(target_frame, width=40)
        self.entry_target.grid(row=0, column=1, padx=5)
        ttk.Button(target_frame, text="?", command=self.show_help, width=2).grid(row=0, column=2)
        target_frame.pack(fill=tk.X, pady=10)

        # Scan Buttons
        scan_frame = ttk.Frame(self.root)
        scans = [
            ("QUICK", "nmap -T4 -F {target}"),
            ("DEEP", "nmap -p- -T4 --min-rate 1000 {target}"),
            ("WEB", "nmap -p 80,443,8080 --script=http-* {target}"),
            ("VULN", "nmap --script vuln,vulners {target}")
        ]
        for text, cmd in scans:
            ttk.Button(scan_frame, text=text,
                      command=lambda c=cmd: self.run_scan(c)).pack(side=tk.LEFT, padx=5, expand=True)
        scan_frame.pack(fill=tk.X, pady=10)

        # Console
        self.console = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=20,
                                               bg=self.fang_gray, fg="white", insertbackground="white")
        self.console.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Action Buttons
        self.action_frame = ttk.Frame(self.root)
        self.action_frame.pack(fill=tk.X, pady=5)

        # Welcome message
        self.log("="*70)
        self.log(ascii_art)
        self.log(subtitle)
        self.log("Version 1.0 | Universal Edition")
        self.log("="*70)
        self.log("Type 'help' for instructions\n")

    def run_scan(self, cmd_template):
        """Execute scanning commands"""
        target = self.entry_target.get()
        if not target:
            self.log("Error: No target specified!")
            return

        cmd = cmd_template.format(target=target)
        if self.is_termux:
            cmd = f"termux-chroot {cmd}"  # Fixes filesystem issues in Termux

        self.log(f"\n=== Starting Scan ===\nCommand: {cmd}")

        try:
            process = subprocess.Popen(cmd, shell=True, 
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     universal_newlines=True)

            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.log(output.strip())

            self.log("\n=== Scan Complete ===")
            self.analyze_results()

        except Exception as e:
            self.log(f"Error: {str(e)}")

    def analyze_results(self):
        """Parse scan results and suggest actions"""
        report = self.console.get("1.0", tk.END)
        
        # Clear old actions
        for widget in self.action_frame.winfo_children():
            widget.destroy()

        # Vulnerability database
        vuln_db = [
            ("Apache", r"(httpd|Apache)", [
                ("Nikto Scan", "nikto -h {target}"),
                ("DirBuster", "dirb http://{target} /usr/share/wordlists/dirb/common.txt")
            ]),
            ("SSH", r"ssh", [
                ("Hydra Brute", "hydra -L users.txt -P passwords.txt {target} ssh"),
                ("SSH Audit", "nmap --script ssh2-enum-algos {target}")
            ]),
            ("MySQL", r"mysql", [
                ("SQLMap", "sqlmap -u 'http://{target}/index.php?id=1' --risk=3"),
                ("Metasploit", "msfconsole -q -x 'use auxiliary/scanner/mysql/mysql_login; set RHOSTS {target}; run'")
            ])
        ]

        # Check for vulnerabilities
        for vuln, pattern, actions in vuln_db:
            if re.search(pattern, report, re.IGNORECASE):
                self.log(f"\nFound: {vuln} Vulnerability")
                self.add_actions(vuln, actions)

        # Check for CVEs
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", report)
        for cve in cves:
            self.log(f"\nDetected CVE: {cve}")
            self.log(f"Research: https://nvd.nist.gov/vuln/detail/{cve}")
            
            # Add exploit buttons for common CVEs
            if "CVE-2017-0144" in cve:
                self.add_action("Exploit EternalBlue", 
                              "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {target}; run'")
            elif "CVE-2021-44228" in cve:
                self.add_action("Exploit Log4Shell",
                              "msfconsole -q -x 'use exploit/multi/misc/log4shell_jndi_injection; set RHOSTS {target}; run'")

        if cves:
            self.log(f"\nFound {len(cves)} CVEs in scan results")

    def add_actions(self, vuln, actions):
        """Add action buttons for detected vulnerabilities"""
        tk.Label(self.action_frame, text=f"{vuln}:").pack(side=tk.LEFT, padx=5)
        for name, cmd in actions:
            cmd = cmd.format(target=self.entry_target.get())
            ttk.Button(self.action_frame, text=name,
                      command=lambda c=cmd: self.log(f"Executing: {c}")).pack(side=tk.LEFT, padx=2)

    def add_action(self, name, cmd_template):
        """Add single action button"""
        cmd = cmd_template.format(target=self.entry_target.get())
        ttk.Button(self.action_frame, text=name,
                  command=lambda: self.log(f"Executing: {cmd}")).pack(side=tk.LEFT, padx=5)

    def log(self, message):
        """Add message to console"""
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)

    def show_help(self):
        """Display help information"""
        help_text = """
FANGSCAN v1.0 - PENETRATION TESTING TOOL

[1] SCAN TYPES:
- QUICK: Fast common port scan
- DEEP: Full port scan with service detection
- WEB: HTTP/HTTPS vulnerability scan
- VULN: CVE detection using Nmap scripts

[2] REQUIREMENTS:
Linux: sudo apt install nmap hydra nikto metasploit
Termux: pkg install nmap hydra nikto metasploit

[3] LEGAL:
Only use on systems you have permission to test!
"""
        messagebox.showinfo("Help", help_text)

    def show_warning(self):
        """Show legal disclaimer"""
        if not messagebox.askokcancel("WARNING", 
                                   "FOR AUTHORIZED TESTING ONLY!\n"
                                   "By continuing you confirm you have permission."):
            self.root.destroy()

def check_dependencies():
    """Verify required tools are installed"""
    required = ['nmap', 'hydra']
    missing = []
    
    for tool in required:
        if not any(os.path.exists(f"{path}/{tool}") for path in os.environ["PATH"].split(":")):
            missing.append(tool)
    
    if missing:
        print(f"Missing tools: {', '.join(missing)}")
        print("Linux: sudo apt install nmap hydra nikto metasploit")
        print("Termux: pkg install nmap hydra nikto metasploit")
        return False
    return True

if __name__ == "__main__":
    if not check_dependencies():
        sys.exit(1)
        
    root = tk.Tk()
    app = FangScan(root)
    root.mainloop()
