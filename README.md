# Paint-
# OsintSpectre v3.0

A modular, production-grade OSINT reconnaissance dashboard.
Formerly known as "Paint-" — fully rewritten for performance, security, and depth.

## Features

- **Email Lookup** — Hunter.io verification, EmailRep reputation, Dehashed breach search,
  Gravatar profile, MX records, social profile probing
- **Username Lookup** — 25+ social platform presence detection, Dehashed search, Google dorking
- **Phone Lookup** — International format parsing, carrier/geolocation/timezone, Dehashed search
- **Domain Lookup** — DNS records, WHOIS, VirusTotal, CRTSH subdomains, tech detection,
  security headers, port scanning, zone transfer, Wayback Machine snapshots
- **IP Lookup** — Reverse DNS, geolocation, Shodan, VirusTotal, port scanning + banner grabbing,
  RDAP, AbuseIPDB check

## Quick Start

```bash
git clone <repo-url>
cd osint-spectre
cp .env.example .env
pip install -r requirements.txt
python app.py
