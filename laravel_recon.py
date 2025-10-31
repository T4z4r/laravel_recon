#!/usr/bin/env python3
"""
Laravel Passive Recon Tool - Full Edition
Passive reconnaissance: Headers, robots.txt, sitemap.xml, .git leaks
Supports: Online (URL) and Offline (local path)
Features: JSON/HTML reports, logging, robust error handling
Author: Grok (xAI)
"""

import os
import re
import sys
import json
import argparse
import logging
import hashlib
import threading
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from colorama import init, Fore, Style
import git
from jinja2 import Environment, FileSystemLoader
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
except ImportError:
    tk = None

# Initialize colorama
init(autoreset=True)

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# =========================
# LaravelRecon Class
# =========================
class LaravelRecon:
    def __init__(self, target, offline=False, timeout=10, output_dir="reports"):
        self.target = target.rstrip("/") if not offline else str(Path(target).resolve())
        self.offline = offline
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; LaravelRecon/2.0)'
        })
        self.is_laravel = False
        self.results = {
            "target": self.target,
            "mode": "offline" if offline else "online",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "laravel_detected": False,
            "findings": []
        }
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    # -------------------------
    # Helper: Add finding
    # -------------------------
    def add_finding(self, category, title, description, severity="INFO", details=None):
        finding = {
            "category": category,
            "title": title,
            "description": description,
            "severity": severity.upper(),
            "details": details or {}
        }
        self.results["findings"].append(finding)
        color = {
            "CRITICAL": Fore.RED,
            "HIGH": Fore.MAGENTA,
            "MEDIUM": Fore.YELLOW,
            "LOW": Fore.CYAN,
            "INFO": Fore.WHITE
        }.get(severity.upper(), Fore.WHITE)
        print(f"{color}[{severity}] {title}")

    # =========================
    # ONLINE MODE
    # =========================
    def check_online(self):
        print(f"{Fore.CYAN}[*] Starting ONLINE reconnaissance on: {self.target}")
        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False, allow_redirects=True)
            if response.status_code >= 400:
                self.add_finding("Connection", "Target Unreachable", f"HTTP {response.status_code}", "HIGH")
                return
            self.check_laravel_framework(response)
            self.check_headers(response)
            self.check_robots()
            self.check_sitemap()
            self.check_git_exposure()
        except requests.exceptions.RequestException as e:
            self.add_finding("Connection", "Request Failed", str(e), "HIGH")

    def check_laravel_framework(self, response):
        headers = response.headers
        content = response.text.lower()
        cookies = response.cookies

        indicators = [
            'laravel' in str(headers).lower(),
            any('laravel_session' in c.name.lower() for c in cookies),
            'x-ratelimit' in headers,
            re.search(r'laravel|artisan|octane', content),
            'csrf' in content and 'laravel' in content
        ]

        if any(indicators):
            self.is_laravel = True
            self.results["laravel_detected"] = True
            self.add_finding("Framework", "Laravel Detected", "Target is running Laravel", "INFO")

    def check_headers(self, response):
        print(f"\n{Fore.CYAN}[*] Analyzing HTTP Headers...")
        headers = response.headers
        important = {
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'X-XSS-Protection': 'Legacy XSS protection',
            'Content-Security-Policy': 'Mitigates XSS',
            'Referrer-Policy': 'Controls referrer',
            'Permissions-Policy': 'Feature control',
            'Strict-Transport-Security': 'Enforces HTTPS',
            'Server': 'Should not leak versions'
        }

        missing = []
        for h, desc in important.items():
            if h not in headers:
                missing.append((h, desc))
                self.add_finding("Security Headers", f"Missing: {h}", desc, "MEDIUM")
            else:
                self.add_finding("Security Headers", f"{h}: {headers[h]}", "Present", "INFO")

        if missing:
            print(f"  {Fore.YELLOW}{len(missing)} security headers missing")

    def check_robots(self):
        print(f"\n{Fore.CYAN}[*] Fetching robots.txt...")
        url = urljoin(self.target + "/", "robots.txt")
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code == 200:
                self.add_finding("robots.txt", "robots.txt Found", f"{len(r.text)} bytes", "INFO",
                                 {"url": url, "disallowed": []})
                disallowed = []
                for line in r.text.splitlines():
                    if line.strip().startswith("Disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            disallowed.append(path)
                            if len(disallowed) <= 10:
                                print(f"    • {path}")
                self.results["findings"][-1]["details"]["disallowed"] = disallowed
            else:
                self.add_finding("robots.txt", "robots.txt Not Found", "404", "LOW")
        except:
            self.add_finding("robots.txt", "robots.txt Error", "Failed to fetch", "LOW")

    def check_sitemap(self):
        print(f"\n{Fore.CYAN}[*] Fetching sitemap.xml...")
        url = urljoin(self.target + "/", "sitemap.xml")
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code == 200:
                urls = re.findall(r'<loc>(.*?)</loc>', r.text)[:5]
                self.add_finding("sitemap.xml", "sitemap.xml Found", f"{len(r.text)} bytes", "INFO",
                                 {"url": url, "sample_urls": urls})
                for u in urls:
                    print(f"    • {u}")
            else:
                self.add_finding("sitemap.xml", "sitemap.xml Not Found", "404", "LOW")
        except:
            self.add_finding("sitemap.xml", "sitemap.xml Error", "Failed to fetch", "LOW")

    def check_git_exposure(self):
        print(f"\n{Fore.CYAN}[*] Checking .git exposure...")
        url = urljoin(self.target + "/", ".git/HEAD")
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code == 200 and "ref:" in r.text:
                self.add_finding("Git Exposure", ".git Directory Exposed!", "CRITICAL RISK", "CRITICAL",
                                 {"url": url, "content": r.text.strip()[:200]})
                print(f"{Fore.RED}    → {url}")
            else:
                self.add_finding("Git Exposure", ".git Not Exposed", "Safe", "INFO")
        except:
            self.add_finding("Git Exposure", ".git Check Failed", "Network error", "LOW")

    # =========================
    # OFFLINE MODE
    # =========================
    def check_offline(self):
        path = Path(self.target)
        if not path.exists() or not path.is_dir():
            self.add_finding("Path", "Invalid Directory", f"{self.target} not found", "HIGH")
            return

        print(f"{Fore.CYAN}[*] Starting OFFLINE reconnaissance on: {path}")
        self.detect_laravel_offline(path)
        self.check_local_git_leaks(path)
        self.check_env_files(path)

    def detect_laravel_offline(self, path):
        markers = [
            path / "artisan",
            path / "app" / "Http" / "Kernel.php",
            path / "composer.json",
            path / "public" / "index.php",
            path / "routes" / "web.php"
        ]
        found = sum(m.exists() for m in markers)
        if found >= 3:
            self.is_laravel = True
            self.results["laravel_detected"] = True
            self.add_finding("Framework", "Laravel Project", f"{found}/5 markers", "INFO")
        else:
            self.add_finding("Framework", "Not Laravel", f"Only {found}/5 markers", "LOW")

    def check_local_git_leaks(self, path):
        git_path = path / ".git"
        if not git_path.exists():
            self.add_finding("Git", "No .git Directory", "Good", "INFO")
            return

        self.add_finding("Git", ".git Directory Found", "Potential leak if web-exposed", "HIGH",
                         {"path": str(git_path)})

        public_git = path / "public" / ".git"
        if public_git.exists():
            self.add_finding("Git", ".git in Web Root!", "CRITICAL - Remove immediately", "CRITICAL")

        try:
            repo = git.Repo(path)
            env_commits = list(repo.iter_commits(paths='.env'))
            if env_commits:
                self.add_finding("Git History", ".env in Git History", f"{len(env_commits)} commits", "CRITICAL",
                                 {"commits": [c.hexsha[:8] for c in env_commits[:5]]})
        except Exception as e:
            self.add_finding("Git", "Git Repo Error", str(e), "LOW")

    def check_env_files(self, path):
        env_files = list(path.rglob(".env*"))
        if not env_files:
            self.add_finding(".env", "No .env Files", "Good", "INFO")
            return

        for env in env_files:
            rel = env.relative_to(path)
            if any(x in str(rel) for x in ["example", "sample", "dist"]):
                self.add_finding(".env", f"Example: {rel}", "Template", "INFO")
            else:
                size = env.stat().st_size
                secrets = []
                try:
                    with open(env, "r", errors="ignore") as f:
                        content = f.read(2048)
                        secrets = re.findall(r"(APP_KEY|DB_PASSWORD|API_|SECRET|TOKEN)=[^\\s\"']+", content)
                except:
                    pass
                if secrets:
                    self.add_finding(".env", f"Leaked .env: {rel}", f"{len(secrets)} secrets", "CRITICAL",
                                     {"path": str(rel), "secrets": secrets[:5]})
                else:
                    self.add_finding(".env", f"Live .env: {rel}", f"{size} bytes", "HIGH")

    # =========================
    # REPORTING
    # =========================
    def save_json_report(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"laravel_recon_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\n{Fore.GREEN}[+] JSON report saved: {filename}")

    def save_html_report(self):
        env = Environment(loader=FileSystemLoader('.'))
        try:
            template = env.get_template("templates/report.html")
        except:
            self.create_html_template()
            template = env.get_template("templates/report.html")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        html = template.render(
            results=self.results,
            timestamp=timestamp,
            total_findings=len(self.results["findings"]),
            critical=len([f for f in self.results["findings"] if f["severity"] == "CRITICAL"])
        )
        filename = self.output_dir / f"laravel_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, "w") as f:
            f.write(html)
        print(f"{Fore.GREEN}[+] HTML report saved: {filename}")

    def create_html_template(self):
        os.makedirs("templates", exist_ok=True)
        template = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Laravel Recon Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }
    .container { max-width: 1000px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
    h1 { color: #2c3e50; }
    .badge { padding: 4px 8px; border-radius: 4px; color: white; font-weight: bold; }
    .critical { background: #e74c3c; }
    .high { background: #e67e22; }
    .medium { background: #f1c40f; }
    .low { background: #3498db; }
    .info { background: #2ecc71; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
    th { background: #f2f2f2; }
    pre { background: #f8f8f8; padding: 10px; border-radius: 4px; overflow-x: auto; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Laravel Passive Recon Report</h1>
    <p><strong>Target:</strong> {{ results.target }} (<em>{{ results.mode|capitalize }}</em>)</p>
    <p><strong>Time:</strong> {{ timestamp }}</p>
    <p><strong>Findings:</strong> {{ total_findings }} | <span class="badge critical">Critical: {{ critical }}</span></p>

    {% for f in results.findings %}
    <div style="margin: 20px 0; padding: 15px; border-left: 5px solid #{{ 'e74c3c' if f.severity == 'CRITICAL' else 'e67e22' if f.severity == 'HIGH' else 'f1c40f' if f.severity == 'MEDIUM' else '3498db' }}; background: #f9f9f9;">
      <h3>[{{ f.severity }}] {{ f.title }}</h3>
      <p>{{ f.description }}</p>
      {% if f.details %}
      <pre>{{ f.details|pprint }}</pre>
      {% endif %}
    </div>
    {% endfor %}
  </div>
</body>
</html>"""
        with open("templates/report.html", "w") as f:
            f.write(template)

# =========================
# GUI
# =========================
class LaravelReconGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Laravel Recon Tool")
        self.root.geometry("800x600")

        # Variables
        self.target_var = tk.StringVar()
        self.mode_var = tk.StringVar(value="online")
        self.timeout_var = tk.IntVar(value=10)
        self.output_dir_var = tk.StringVar(value="reports")
        self.dark_mode = tk.BooleanVar(value=False)
        self.recon = None
        self.results_text = None

        # Set app icon
        try:
            self.root.iconbitmap("icon.ico")
        except:
            pass  # Icon not found, continue without it

        self.create_styles()
        self.create_widgets()
        self.apply_theme()

        # Bind dark mode toggle
        self.dark_mode.trace_add("write", lambda *args: self.apply_theme())

    def create_styles(self):
        self.style = ttk.Style()
        # Light theme (default) - Blue neon accents
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", foreground="#000000")
        self.style.configure("TButton", background="#e0e0e0", foreground="#000000")
        self.style.configure("TRadiobutton", background="#f0f0f0", foreground="#000000")
        self.style.configure("TEntry", fieldbackground="#ffffff", foreground="#000000")
        self.style.configure("TSpinbox", fieldbackground="#ffffff", foreground="#000000")

        # Dark theme - Blue neon
        self.style.configure("Dark.TFrame", background="#0a0a0a")
        self.style.configure("Dark.TLabel", background="#0a0a0a", foreground="#00ffff")
        self.style.configure("Dark.TButton", background="#1a1a1a", foreground="#00ffff", bordercolor="#00ffff")
        self.style.configure("Dark.TRadiobutton", background="#0a0a0a", foreground="#00ffff")
        self.style.configure("Dark.TEntry", fieldbackground="#1a1a1a", foreground="#00ffff", bordercolor="#00ffff")
        self.style.configure("Dark.TSpinbox", fieldbackground="#1a1a1a", foreground="#00ffff", bordercolor="#00ffff")
        self.style.configure("Dark.TCheckbutton", background="#0a0a0a", foreground="#00ffff")

        # Custom styles for neon effects
        self.style.map("Dark.TButton",
            background=[("active", "#003d4d")],
            foreground=[("active", "#ffffff")])
        self.style.map("Dark.TEntry",
            fieldbackground=[("focus", "#003d4d")])
        self.style.map("Dark.TSpinbox",
            fieldbackground=[("focus", "#003d4d")])

    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Logo/Title frame
        logo_frame = ttk.Frame(main_frame)
        logo_frame.grid(row=0, column=0, columnspan=4, pady=(0, 10))

        # Metasploit-like logo text
        logo_label = tk.Label(logo_frame, text="LARAVEL RECON", font=("Courier", 16, "bold"), fg="#00ffff", bg="#0a0a0a")
        logo_label.pack()

        # Subtitle
        subtitle_label = tk.Label(logo_frame, text="Passive Reconnaissance Tool", font=("Courier", 8), fg="#00ffff", bg="#0a0a0a")
        subtitle_label.pack()

        # Dark mode toggle
        ttk.Checkbutton(main_frame, text="Dark Mode", variable=self.dark_mode).grid(row=1, column=3, sticky=tk.E, pady=5)

        # Target input
        ttk.Label(main_frame, text="Target:").grid(row=2, column=0, sticky=tk.W, pady=5)
        target_entry = ttk.Entry(main_frame, textvariable=self.target_var, width=50)
        target_entry.grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        # Mode selection
        ttk.Label(main_frame, text="Mode:").grid(row=3, column=0, sticky=tk.W, pady=5)
        mode_frame = ttk.Frame(main_frame)
        mode_frame.grid(row=3, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        ttk.Radiobutton(mode_frame, text="Online (URL)", variable=self.mode_var, value="online").pack(side=tk.LEFT)
        ttk.Radiobutton(mode_frame, text="Offline (Path)", variable=self.mode_var, value="offline").pack(side=tk.LEFT)

        # Timeout
        ttk.Label(main_frame, text="Timeout (s):").grid(row=4, column=0, sticky=tk.W, pady=5)
        ttk.Spinbox(main_frame, from_=1, to=60, textvariable=self.timeout_var, width=10).grid(row=4, column=1, sticky=tk.W, pady=5)

        # Output directory
        ttk.Label(main_frame, text="Output Dir:").grid(row=5, column=0, sticky=tk.W, pady=5)
        output_entry = ttk.Entry(main_frame, textvariable=self.output_dir_var, width=40)
        output_entry.grid(row=5, column=1, sticky=(tk.W, tk.E), pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_output_dir).grid(row=5, column=2, pady=5)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=4, pady=10)
        ttk.Button(button_frame, text="Start Recon", command=self.start_recon).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save JSON", command=self.save_json).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save HTML", command=self.save_html).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_results).pack(side=tk.LEFT, padx=5)

        # Results area
        ttk.Label(main_frame, text="Results:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.results_text = scrolledtext.ScrolledText(main_frame, height=20, wrap=tk.WORD)
        self.results_text.grid(row=8, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(8, weight=1)

        # Store references for theme switching
        self.main_frame = main_frame
        self.target_entry = target_entry
        self.output_entry = output_entry
        self.mode_frame = mode_frame
        self.button_frame = button_frame
        self.logo_frame = logo_frame
        self.logo_label = logo_label
        self.subtitle_label = subtitle_label

    def apply_theme(self):
        if self.dark_mode.get():
            # Apply dark blue neon theme
            self.root.configure(bg="#0a0a0a")
            self.main_frame.configure(style="Dark.TFrame")
            self.target_entry.configure(style="Dark.TEntry")
            self.output_entry.configure(style="Dark.TEntry")

            # Update logo colors
            self.logo_label.configure(fg="#00ffff", bg="#0a0a0a")
            self.subtitle_label.configure(fg="#00ffff", bg="#0a0a0a")

            # Update all labels
            for child in self.main_frame.winfo_children():
                if isinstance(child, ttk.Label):
                    child.configure(style="Dark.TLabel")
                elif isinstance(child, ttk.Button):
                    child.configure(style="Dark.TButton")
                elif isinstance(child, ttk.Checkbutton):
                    child.configure(style="Dark.TCheckbutton")
                elif isinstance(child, ttk.Frame):
                    for subchild in child.winfo_children():
                        if isinstance(subchild, ttk.Radiobutton):
                            subchild.configure(style="Dark.TRadiobutton")

            # Update results text area with neon blue
            self.results_text.configure(bg="#0a0a0a", fg="#00ffff", insertbackground="#00ffff")
        else:
            # Apply light theme
            self.root.configure(bg="#f0f0f0")
            self.main_frame.configure(style="TFrame")
            self.target_entry.configure(style="TEntry")
            self.output_entry.configure(style="TEntry")

            # Update logo colors for light theme
            self.logo_label.configure(fg="#000000", bg="#f0f0f0")
            self.subtitle_label.configure(fg="#666666", bg="#f0f0f0")

            # Update all labels
            for child in self.main_frame.winfo_children():
                if isinstance(child, ttk.Label):
                    child.configure(style="TLabel")
                elif isinstance(child, ttk.Button):
                    child.configure(style="TButton")
                elif isinstance(child, ttk.Checkbutton):
                    child.configure(style="TCheckbutton")
                elif isinstance(child, ttk.Frame):
                    for subchild in child.winfo_children():
                        if isinstance(subchild, ttk.Radiobutton):
                            subchild.configure(style="TRadiobutton")

            # Update results text area
            self.results_text.configure(bg="#ffffff", fg="#000000", insertbackground="#000000")

    def browse_output_dir(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.output_dir_var.set(dir_path)

    def start_recon(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL or path")
            return

        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Starting reconnaissance...\n")

        # Disable button
        self.root.config(cursor="wait")
        self.root.update()

        # Run in thread to avoid freezing GUI
        thread = threading.Thread(target=self.run_recon, args=(target,))
        thread.start()

    def run_recon(self, target):
        try:
            self.recon = LaravelRecon(
                target=target,
                offline=self.mode_var.get() == "offline",
                timeout=self.timeout_var.get(),
                output_dir=self.output_dir_var.get()
            )

            if self.mode_var.get() == "online":
                self.recon.check_online()
            else:
                self.recon.check_offline()

            # Display results
            self.display_results()

        except Exception as e:
            self.results_text.insert(tk.END, f"Error: {str(e)}\n")
        finally:
            self.root.config(cursor="")
            self.root.update()

    def display_results(self):
        if not self.recon:
            return

        self.results_text.insert(tk.END, f"\nTarget: {self.recon.target}\n")
        self.results_text.insert(tk.END, f"Mode: {self.recon.results['mode']}\n")
        self.results_text.insert(tk.END, f"Laravel Detected: {self.recon.results['laravel_detected']}\n")
        self.results_text.insert(tk.END, f"Total Findings: {len(self.recon.results['findings'])}\n\n")

        for finding in self.recon.results["findings"]:
            self.results_text.insert(tk.END, f"[{finding['severity']}] {finding['title']}\n")
            self.results_text.insert(tk.END, f"{finding['description']}\n")
            if finding['details']:
                self.results_text.insert(tk.END, f"Details: {finding['details']}\n")
            self.results_text.insert(tk.END, "\n")

    def save_json(self):
        if not self.recon:
            messagebox.showwarning("Warning", "No results to save. Run reconnaissance first.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w") as f:
                    json.dump(self.recon.results, f, indent=2)
                messagebox.showinfo("Success", f"JSON report saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save JSON: {str(e)}")

    def save_html(self):
        if not self.recon:
            messagebox.showwarning("Warning", "No results to save. Run reconnaissance first.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
        )
        if file_path:
            try:
                env = Environment(loader=FileSystemLoader('.'))
                try:
                    template = env.get_template("templates/report.html")
                except:
                    self.recon.create_html_template()
                    template = env.get_template("templates/report.html")

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
                html = template.render(
                    results=self.recon.results,
                    timestamp=timestamp,
                    total_findings=len(self.recon.results["findings"]),
                    critical=len([f for f in self.recon.results["findings"] if f["severity"] == "CRITICAL"])
                )
                with open(file_path, "w") as f:
                    f.write(html)
                messagebox.showinfo("Success", f"HTML report saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save HTML: {str(e)}")

    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.recon = None

def launch_gui():
    if tk is None:
        print("tkinter not available. Install tkinter to use GUI.")
        return

    root = tk.Tk()
    LaravelReconGUI(root)
    root.mainloop()

# =========================
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(description="Laravel Passive Recon Tool - Full Edition")
    parser.add_argument('--gui', action='store_true', help='Launch GUI mode')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-u', '--url', help='Target URL (e.g. https://example.com)')
    group.add_argument('-p', '--path', help='Local Laravel project path')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--json', action='store_true', help='Save JSON report')
    parser.add_argument('--html', action='store_true', help='Save HTML report')
    parser.add_argument('-o', '--output', default='reports', help='Output directory')
    args = parser.parse_args()

    if args.gui:
        launch_gui()
        return

    recon = LaravelRecon(
        target=args.url or args.path,
        offline=bool(args.path),
        timeout=args.timeout,
        output_dir=args.output
    )

    if args.url:
        recon.check_online()
    else:
        recon.check_offline()

    # Save reports
    if args.json or args.html:
        if args.json:
            recon.save_json_report()
        if args.html:
            recon.save_html_report()
    else:
        # Default: save both
        recon.save_json_report()
        recon.save_html_report()

    print(f"\n{Style.BRIGHT}{Fore.CYAN}Recon complete.")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Interrupted by user.")
        sys.exit(1)