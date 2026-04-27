import os
import json
import time
import threading
import re
import hashlib
import hmac
import requests
import socket
import dns.resolver
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(64).hex())
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'False') == 'True'

# Task storage (in-memory, persists during session)
tasks = {}

# ─── API KEYS ────────────────────────────────────────────────────────────────
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
HUNTER_API_KEY = os.environ.get('HUNTER_API_KEY', '')
DEHASHED_EMAIL = os.environ.get('DEHASHED_EMAIL', '')
DEHASHED_API_KEY = os.environ.get('DEHASHED_API_KEY', '')
# ─────────────────────────────────────────────────────────────────────────────

ua = UserAgent()

# ═══════════════════════════════════════════════════════════════════════════════
# BACKGROUND TASK WORKER
# ═══════════════════════════════════════════════════════════════════════════════

def background_lookup(task_id, query_type, target):
    """Runs in a background thread so the UI doesn't block."""
    tasks[task_id] = {'status': 'running', 'progress': 0, 'results': {}, 'error': None}
    try:
        if query_type == 'email':
            tasks[task_id]['results'] = lookup_email(target, task_id)
        elif query_type == 'username':
            tasks[task_id]['results'] = lookup_username(target, task_id)
        elif query_type == 'phone':
            tasks[task_id]['results'] = lookup_phone(target, task_id)
        elif query_type == 'domain':
            tasks[task_id]['results'] = lookup_domain(target, task_id)
        elif query_type == 'ip':
            tasks[task_id]['results'] = lookup_ip(target, task_id)
        tasks[task_id]['status'] = 'complete'
        tasks[task_id]['progress'] = 100
    except Exception as e:
        tasks[task_id]['status'] = 'error'
        tasks[task_id]['error'] = str(e)

# ═══════════════════════════════════════════════════════════════════════════════
# LOOKUP FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def lookup_email(email, task_id):
    results = {}
    tasks[task_id]['progress'] = 10

    # 1. Have I Been Pwned (public)
    try:
        sha1 = hashlib.sha1(email.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        r = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=10)
        if r.status_code == 200:
            found = [line.split(':') for line in r.text.splitlines() if line.startswith(suffix)]
            results['hibp'] = {'breached': len(found) > 0, 'count': int(found[0][1]) if found else 0}
    except:
        results['hibp'] = {'error': 'Could not check HIBP'}

    tasks[task_id]['progress'] = 25

    # 2. Hunter.io (if key set)
    if HUNTER_API_KEY:
        try:
            r = requests.get(f'https://api.hunter.io/v2/email-verifier?email={email}&api_key={HUNTER_API_KEY}', timeout=10)
            if r.status_code == 200:
                results['hunter'] = r.json().get('data', {})
        except:
            results['hunter'] = {'error': 'Hunter API error'}

    tasks[task_id]['progress'] = 40

    # 3. EmailRep
    try:
        r = requests.get(f'https://emailrep.io/{email}', headers={'User-Agent': ua.random}, timeout=10)
        if r.status_code == 200:
            results['emailrep'] = r.json()
    except:
        pass

    tasks[task_id]['progress'] = 55

    # 4. Dehashed (if keys set)
    if DEHASHED_EMAIL and DEHASHED_API_KEY:
        try:
            r = requests.get(
                f'https://api.dehashed.com/search?query=email:{email}',
                auth=(DEHASHED_EMAIL, DEHASHED_API_KEY),
                headers={'Accept': 'application/json'},
                timeout=15
            )
            if r.status_code == 200:
                data = r.json()
                results['dehashed'] = {
                    'total': data.get('total', 0),
                    'entries': data.get('entries', [])[:10]
                }
        except:
            results['dehashed'] = {'error': 'Dehashed API error'}

    tasks[task_id]['progress'] = 70

    # 5. Gravatar
    try:
        md5 = hashlib.md5(email.lower().encode()).hexdigest()
        r = requests.get(f'https://www.gravatar.com/{md5}.json', timeout=10)
        if r.status_code == 200:
            results['gravatar'] = r.json().get('entry', [{}])[0]
    except:
        pass

    tasks[task_id]['progress'] = 85

    # 6. Google dork-style profile search
    try:
        sites_found = []
        for site in ['github.com', 'twitter.com', 'linkedin.com', 'facebook.com']:
            r = requests.get(
                f'https://www.google.com/search?q=site:{site}+%22{email}%22',
                headers={'User-Agent': ua.random},
                timeout=8
            )
            if email.lower() in r.text.lower():
                sites_found.append(site)
        if sites_found:
            results['profiles'] = {'sites': sites_found}
    except:
        pass

    tasks[task_id]['progress'] = 100
    return results


def lookup_username(username, task_id):
    results = {}
    tasks[task_id]['progress'] = 10

    sites = {
        'GitHub': f'https://github.com/{username}',
        'Twitter/X': f'https://x.com/{username}',
        'Instagram': f'https://www.instagram.com/{username}/',
        'Reddit': f'https://www.reddit.com/user/{username}',
        'Medium': f'https://medium.com/@{username}',
        'Pinterest': f'https://www.pinterest.com/{username}/',
        'TikTok': f'https://www.tiktok.com/@{username}',
        'YouTube': f'https://www.youtube.com/@{username}',
        'Twitch': f'https://www.twitch.tv/{username}',
        'Telegram': f'https://t.me/{username}',
        'Keybase': f'https://keybase.io/{username}',
        'Mastodon': f'https://mastodon.social/@{username}',
        'DeviantArt': f'https://www.deviantart.com/{username}',
        'Steam': f'https://steamcommunity.com/id/{username}',
        'WordPress': f'https://{username}.wordpress.com/',
        'Replit': f'https://replit.com/@{username}',
        'Chess.com': f'https://www.chess.com/member/{username}',
        'Spotify': f'https://open.spotify.com/user/{username}',
        'Pastebin': f'https://pastebin.com/u/{username}',
        'HackerNews': f'https://news.ycombinator.com/user?id={username}',
    }

    found = []
    total = len(sites)
    for i, (site, url) in enumerate(sites.items()):
        try:
            r = requests.get(url, headers={'User-Agent': ua.random}, timeout=5, allow_redirects=True)
            if r.status_code == 200:
                found.append({'site': site, 'url': url, 'status': 'found'})
            elif r.status_code == 403:
                found.append({'site': site, 'url': url, 'status': 'blocked'})
        except:
            pass
        tasks[task_id]['progress'] = int(10 + (i + 1) / total * 80)

    results['profiles'] = found

    # Check pastebin for username mentions
    tasks[task_id]['progress'] = 90
    try:
        r = requests.get(f'https://psbdmp.ws/api/search/{username}', headers={'User-Agent': ua.random}, timeout=10)
        if r.status_code == 200:
            results['pastes'] = r.json()[:10]
    except:
        pass

    tasks[task_id]['progress'] = 100
    return results


def lookup_phone(phone, task_id):
    results = {}
    tasks[task_id]['progress'] = 15

    try:
        parsed = phonenumbers.parse(phone, None) if '+' in phone else phonenumbers.parse(phone, 'US')
        results['parsed'] = {
            'international': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            'national': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            'country': geocoder.description_for_number(parsed, 'en'),
            'carrier': carrier.name_for_number(parsed, 'en'),
            'timezones': timezone.time_zones_for_number(parsed),
            'valid': phonenumbers.is_valid_number(parsed),
            'possible': phonenumbers.is_possible_number(parsed),
        }
    except:
        results['parsed'] = {'error': 'Invalid phone number'}

    tasks[task_id]['progress'] = 40

    # Check online
    try:
        r = requests.get(
            f'https://www.google.com/search?q=%22{phone}%22',
            headers={'User-Agent': ua.random},
            timeout=8
        )
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            results['google_mentions'] = max(0, len(soup.select('div.g')) - 2)
    except:
        pass

    tasks[task_id]['progress'] = 70

    # Numverify-style check
    try:
        r = requests.get(
            f'https://apilayer.net/api/validate?number={phone}',
            headers={'User-Agent': ua.random},
            timeout=10
        )
        if r.status_code == 200:
            results['validation_api'] = r.json()
    except:
        pass

    tasks[task_id]['progress'] = 100
    return results


def lookup_domain(domain, task_id):
    results = {}
    tasks[task_id]['progress'] = 10

    # DNS records
    try:
        records = {}
        for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, qtype, lifetime=5)
                records[qtype] = [str(r) for r in answers]
            except:
                records[qtype] = []
        results['dns'] = records
    except:
        results['dns'] = {'error': 'DNS lookup failed'}

    tasks[task_id]['progress'] = 25

    # WHOIS-style
    try:
        r = requests.get(f'https://who.is/whois/{domain}', headers={'User-Agent': ua.random}, timeout=10)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            pre = soup.find('pre')
            if pre:
                results['whois'] = pre.get_text()[:2000]
    except:
        pass

    tasks[task_id]['progress'] = 40

    # Shodan (if key set)
    if SHODAN_API_KEY:
        try:
            r = requests.get(
                f'https://api.shodan.io/dns/resolve?hostnames={domain}&key={SHODAN_API_KEY}',
                timeout=10
            )
            if r.status_code == 200:
                ip = r.json().get(domain)
                if ip:
                    r2 = requests.get(
                        f'https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}',
                        timeout=10
                    )
                    if r2.status_code == 200:
                        data = r2.json()
                        results['shodan'] = {
                            'ip': ip,
                            'ports': data.get('ports', []),
                            'services': [s.get('service', '') for s in data.get('data', [])[:10]],
                            'vulns': list(data.get('vulns', {}).keys()) if data.get('vulns') else [],
                            'org': data.get('org', ''),
                            'country': data.get('country_name', ''),
                        }
        except:
            results['shodan'] = {'error': 'Shodan API error'}

    tasks[task_id]['progress'] = 55

    # crt.sh (certificate transparency)
    try:
        r = requests.get(f'https://crt.sh/?q={domain}&output=json', headers={'User-Agent': ua.random}, timeout=15)
        if r.status_code == 200:
            data = r.json()
            subdomains = set()
            for entry in data[:50]:
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    if sub.endswith(f'.{domain}') or sub == domain:
                        subdomains.add(sub)
            results['subdomains'] = sorted(list(subdomains))[:30]
    except:
        pass

    tasks[task_id]['progress'] = 70

    # Wayback Machine
    try:
        r = requests.get(
            f'https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=20&fl=original,timestamp',
            headers={'User-Agent': ua.random},
            timeout=10
        )
        if r.status_code == 200 and len(r.json()) > 1:
            results['wayback'] = [{'url': item[0], 'date': item[1]} for item in r.json()[1:]][:15]
    except:
        pass

    tasks[task_id]['progress'] = 85

    # Security headers
    try:
        r = requests.get(f'https://{domain}', headers={'User-Agent': ua.random}, timeout=10)
        headers_info = {}
        interesting = ['server', 'x-powered-by', 'x-frame-options', 'content-security-policy',
                       'strict-transport-security', 'x-content-type-options', 'set-cookie']
        for h in interesting:
            if h in r.headers:
                headers_info[h] = r.headers[h]
        results['headers'] = headers_info
    except:
        pass

    tasks[task_id]['progress'] = 100
    return results


def lookup_ip(ip, task_id):
    results = {}
    tasks[task_id]['progress'] = 15

    # Basic info
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        results['hostname'] = hostname
    except:
        results['hostname'] = None

    # IP geolocation
    try:
        r = requests.get(f'https://ipapi.co/{ip}/json/', headers={'User-Agent': ua.random}, timeout=10)
        if r.status_code == 200:
            results['geo'] = r.json()
    except:
        pass

    # Alternative geo source
    if 'geo' not in results:
        try:
            r = requests.get(f'https://ipwho.is/{ip}', headers={'User-Agent': ua.random}, timeout=10)
            if r.status_code == 200:
                results['geo'] = r.json()
        except:
            pass

    tasks[task_id]['progress'] = 35

    # Shodan
    if SHODAN_API_KEY:
        try:
            r = requests.get(
                f'https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}',
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                results['shodan'] = {
                    'ports': data.get('ports', []),
                    'services': [s.get('service', '') for s in data.get('data', [])[:15]],
                    'vulns': list(data.get('vulns', {}).keys()) if data.get('vulns') else [],
                    'org': data.get('org', ''),
                    'isp': data.get('isp', ''),
                    'country': data.get('country_name', ''),
                    'city': data.get('city', ''),
                    'os': data.get('os', ''),
                }
        except:
            results['shodan'] = {'error': 'Shodan error'}

    tasks[task_id]['progress'] = 55

    # Open ports scan (common ports)
    try:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                        1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017]
        open_ports = []
        for port in common_ports[:15]:  # limit to first 15 for speed
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        results['open_ports'] = open_ports
    except:
        results['open_ports'] = []

    tasks[task_id]['progress'] = 75

    # Reverse DNS
    try:
        answers = dns.resolver.resolve_address(ip, lifetime=5)
        results['reverse_dns'] = [str(a) for a in answers]
    except:
        results['reverse_dns'] = []

    tasks[task_id]['progress'] = 90

    # AbuseIPDB check
    try:
        r = requests.get(
            f'https://www.abuseipdb.com/check/{ip}',
            headers={'User-Agent': ua.random},
            timeout=10
        )
        if r.status_code == 200 and 'abuse-confidence' in r.text:
            soup = BeautifulSoup(r.text, 'lxml')
            conf = soup.find('span', class_='abuse-confidence')
            if conf:
                results['abuse_score'] = conf.get_text().strip()
    except:
        pass

    tasks[task_id]['progress'] = 100
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/lookup', methods=['POST'])
def start_lookup():
    data = request.get_json()
    query_type = data.get('type', '').lower()
    target = data.get('target', '').strip()

    if not query_type or not target:
        return jsonify({'error': 'Missing query type or target'}), 400

    if query_type not in ['email', 'username', 'phone', 'domain', 'ip']:
        return jsonify({'error': 'Invalid query type'}), 400

    task_id = hashlib.md5(f'{query_type}:{target}:{time.time()}'.encode()).hexdigest()[:12]
    tasks[task_id] = {'status': 'queued', 'progress': 0, 'results': {}, 'error': None}

    thread = threading.Thread(target=background_lookup, args=(task_id, query_type, target))
    thread.daemon = True
    thread.start()

    return jsonify({'task_id': task_id, 'status': 'queued'})

@app.route('/api/status/<task_id>')
def get_status(task_id):
    task = tasks.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify(task)

@app.route('/api/config')
def get_config():
    """Show which API keys are configured (without exposing the keys themselves)."""
    return jsonify({
        'shodan': bool(SHODAN_API_KEY),
        'hunter': bool(HUNTER_API_KEY),
        'dehashed': bool(DEHASHED_EMAIL and DEHASHED_API_KEY),
    })

# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
