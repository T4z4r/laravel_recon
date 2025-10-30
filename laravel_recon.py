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
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from colorama import init, Fore, Style
import git
from jinja2 import Environment, FileSystemLoader

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
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(description="Laravel Passive Recon Tool - Full Edition")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Target URL (e.g. https://example.com)')
    group.add_argument('-p', '--path', help='Local Laravel project path')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--json', action='store_true', help='Save JSON report')
    parser.add_argument('--html', action='store_true', help='Save HTML report')
    parser.add_argument('-o', '--output', default='reports', help='Output directory')
    args = parser.parse_args()

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