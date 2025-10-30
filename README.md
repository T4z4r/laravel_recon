# Laravel Passive Recon Tool

A **passive reconnaissance** tool for **Laravel applications**.

Scans for:
- Security headers
- `robots.txt` & `sitemap.xml`
- `.git` exposure
- `.env` leaks in Git history (offline)
- Laravel framework detection

Supports **online** and **offline** modes.

---

## Installation

```bash
git clone https://github.com/T4z4r/laravel-recon.git
cd laravel-recon
pip install -r requirements.txt
chmod +x laravel_recon.py