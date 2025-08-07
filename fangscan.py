#!/usr/bin/env python3
# FANGSCAN v1.0 - Universal Penetration Testing Tool
# Works on Termux and Linux
# Author: MG

import os
import re
import platform
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

class FangScan:
    def __init__(self, root):
        # System detection
        self.is_termux = "termux" in os.environ.get('PREFIX', '')
        self.root = root
        
        # Configure UI
        self.setup_ui()
        self.show_warning()

    def setup_ui(self):
        """Initialize all UI components"""
        # Colors
        self.fang_red = "#d93f3f"
        self.fang_black = "#1a1a1a"
        self.fang_gray = "#333333"

        # Main window
        self.root.title("FANGSCAN v1.0")
        self.root.geometry("800x650")
        self.root.configure(bg=self.fang_black)

        # ASCII Art
        ascii_art = """
███████╗ █████╗ ███╗   ██╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
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