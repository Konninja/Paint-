import time
import re
import hashlib
import socket
import threading
from datetime import datetime

import requests
import dns.resolver
import dns.zone
import dns.query
import phonenumbers
from phonenumbers import carrier as pn_carrier, geocoder as pn_geocoder, timezone as pn_timezone
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
from urllib.parse import quote, urlparse

from config import Config

ua = UserAgent()

# ─── Task Storage ─────────────────────────────────────────────────────
tasks = {}
tasks_lock = threading.Lock()


def get_task(task_id):
    with tasks_lock:
        return tasks.get(task_id)


def set_task(task_id, data):
    with tasks_lock:
        tasks[task_id] = data


def update_progress(task_id, pct):
    with tasks_lock:
        if task_id in tasks:
            tasks[task_id]['progress'] = pct


def background_lookup(task_id, query_type, target):
    set_task(task_id, {
        'status': 'running',
        'progress': 0,
        'results': {},
        'error': None,
        'started_at': datetime.utcnow().isoformat(),
    })
    try:
        target = target.strip()
        if query_type == 'email':
            results = lookup_email(target, task_id)
        elif query_type == 'username':
            results = lookup_username(target, task_id)
        elif query_type == 'phone':
            results = lookup_phone(target, task_id)
        elif query_type == 'domain':
            results = lookup_domain(target, task_id)
        elif query_type == 'ip':
            results = lookup_ip(target, task_id)
        else:
            raise ValueError(f'Unknown query type: {query_type}')

        with tasks_lock:
            tasks[task_id]['results'] = results
            tasks[task_id]['status'] = 'complete'
            tasks[task_id]['finished_at'] = datetime.utcnow().isoformat()
            tasks[task_id]['progress'] = 100

    except Exception as e:
        with tasks_lock:
            tasks[task_id]['status'] = 'error'
            tasks[task_id]['error'] = str(e)
            tasks[task_id]['finished_at'] = datetime.utcnow().isoformat()


# ═══════════════════════════════════════════════════════════════════════
# EMAIL LOOKUP
# ═══════════════════════════════════════════════════════════════════════

def lookup_email(email, task_id):
    results = {}
    email = email.strip().lower()
    if not re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email):
        return {'error': 'Invalid email format'}
    domain = email.split('@')[-1]

    update_progress(task_id, 10)

    # Hunter.io verification
    if Config.HUNTER_API_KEY:
        try:
            r = requests.get(
                'https://api.hunter.io/v2/email-verifier',
                params={'email': email, 'api_key': Config.HUNTER_API_KEY},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json().get('data', {})
                results['hunter_verification'] = {
                    'status': data.get('status'),
                    'score': data.get('score'),
                    'disposable': data.get('disposable'),
                    'webmail': data.get('webmail'),
                    'mx_records': data.get('mx_records'),
                    'smtp_server': data.get('smtp_server'),
                    'smtp_check': data.get('smtp_check'),
                    'gibberish': data.get('gibberish'),
                }
        except Exception:
            pass
    update_progress(task_id, 25)

    # Gravatar
    email_hash = hashlib.md5(email.encode()).hexdigest()
    results['gravatar'] = {
        'hash': email_hash,
        'avatar_url': f'https://www.gravatar.com/avatar/{email_hash}?s=200&d=404',
        'profile_url': f'https://www.gravatar.com/{email_hash}',
    }
    update_progress(task_id, 35)

    # Dehashed
    if Config.DEHASHED_EMAIL and Config.DEHASHED_API_KEY:
        try:
            r = requests.get(
                f'https://api.dehashed.com/search?query=email:{quote(email)}',
                auth=(Config.DEHASHED_EMAIL, Config.DEHASHED_API_KEY),
                headers={'Accept': 'application/json'},
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get('total', 0) > 0:
                    results['dehashed'] = {
                        'total': data['total'],
                        'entries': [
                            {
                                'email': e.get('email'),
                                'username': e.get('username'),
                                'password': e.get('password'),
                                'hashed_password': e.get('hashed_password')[:40] + '...' if e.get('hashed_password') and len(e.get('hashed_password', '')) > 40 else e.get('hashed_password'),
                                'name': e.get('name'),
                                'database_name': e.get('database_name'),
                                'ip': e.get('ip'),
                            }
                            for e in data.get('entries', [])[:20]
                        ],
                    }
        except Exception:
            pass
    update_progress(task_id, 50)

    # EmailRep
    try:
        r = requests.get(
            f'https://emailrep.io/{quote(email)}',
            headers={'User-Agent': ua.random, 'Accept': 'application/json'},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            results['emailrep'] = {
                'reputation': data.get('reputation'),
                'suspicious': data.get('suspicious'),
                'references': data.get('references'),
                'details': data.get('details'),
                'blacklisted': data.get('details', {}).get('blacklisted'),
                'malicious_activity': data.get('details', {}).get('malicious_activity'),
                'credentials_leaked': data.get('details', {}).get('credentials_leaked'),
                'data_breach': data.get('details', {}).get('data_breach'),
            }
    except Exception:
        pass
    update_progress(task_id, 65)

    # MX Records
    try:
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=10)
        results['mx_records'] = [
            {'priority': mx.preference, 'host': str(mx.exchange).rstrip('.')}
            for mx in mx_records
        ]
    except Exception:
        pass
    update_progress(task_id, 80)

    # Social profile checks
    results['social_profiles'] = check_email_social_profiles(email)
    update_progress(task_id, 100)
    return results


def check_email_social_profiles(email):
    profiles = {}
    username = email.split('@')[0]
    sites = {
        'github': f'https://github.com/{quote(username)}',
        'twitter/x': f'https://twitter.com/{quote(username)}',
        'linkedin': f'https://www.linkedin.com/in/{quote(username)}',
        'keybase': f'https://keybase.io/{quote(username)}',
    }
    for site, url in sites.items():
        try:
            r = requests.head(url, headers={'User-Agent': ua.random}, timeout=5, allow_redirects=True)
            profiles[site] = url if r.status_code == 200 else None
        except Exception:
            profiles[site] = None
    return profiles


# ═══════════════════════════════════════════════════════════════════════
# USERNAME LOOKUP
# ═══════════════════════════════════════════════════════════════════════

def lookup_username(username, task_id):
    results = {}
    username = username.strip()
    if len(username) < 2:
        return {'error': 'Username too short'}
    if not re.match(r'^[a-zA-Z0-9_.\-]+$', username):
        return {'error': 'Username contains invalid characters'}

    update_progress(task_id, 10)

    platforms = {
        'GitHub': f'https://github.com/{quote(username)}',
        'Twitter / X': f'https://twitter.com/{quote(username)}',
        'Instagram': f'https://www.instagram.com/{quote(username)}/',
        'Reddit': f'https://www.reddit.com/user/{quote(username)}',
        'Medium': f'https://medium.com/@{quote(username)}',
        'Dev.to': f'https://dev.to/{quote(username)}',
        'Keybase': f'https://keybase.io/{quote(username)}',
        'Pastebin': f'https://pastebin.com/u/{quote(username)}',
        'Replit': f'https://replit.com/@{quote(username)}',
        'Telegram': f'https://t.me/{quote(username)}',
        'Twitch': f'https://www.twitch.tv/{quote(username)}',
        'YouTube': f'https://www.youtube.com/@{quote(username)}',
        'Pinterest': f'https://www.pinterest.com/{quote(username)}/',
        'TikTok': f'https://www.tiktok.com/@{quote(username)}',
        'Facebook': f'https://www.facebook.com/{quote(username)}',
        'GitLab': f'https://gitlab.com/{quote(username)}',
        'HackerNews': f'https://news.ycombinator.com/user?id={quote(username)}',
        'ProductHunt': f'https://www.producthunt.com/@{quote(username)}',
        'Behance': f'https://www.behance.net/{quote(username)}',
        'Dribbble': f'https://dribbble.com/{quote(username)}',
        'BitBucket': f'https://bitbucket.org/{quote(username)}/',
        'Disqus': f'https://disqus.com/by/{quote(username)}/',
        'SlideShare': f'https://www.slideshare.net/{quote(username)}',
        'Vimeo': f'https://vimeo.com/{quote(username)}',
    }
    found = {}
    for name, url in platforms.items():
        try:
            r = requests.head(url, headers={'User-Agent': ua.random}, timeout=5, allow_redirects=True)
            if r.status_code == 200:
                found[name] = url
        except Exception:
            pass
    results['social_media'] = found
    update_progress(task_id, 40)

    # Dehashed
    if Config.DEHASHED_EMAIL and Config.DEHASHED_API_KEY:
        try:
            r = requests.get(
                f'https://api.dehashed.com/search?query=username:{quote(username)}',
                auth=(Config.DEHASHED_EMAIL, Config.DEHASHED_API_KEY),
                headers={'Accept': 'application/json'},
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get('total', 0) > 0:
                    results['dehashed'] = {
                        'total': data['total'],
                        'entries': [
                            {
                                'email': e.get('email'),
                                'username': e.get('username'),
                                'password': e.get('password'),
                                'name': e.get('name'),
                                'database_name': e.get('database_name'),
                            }
                            for e in data.get('entries', [])[:20]
                        ],
                    }
        except Exception:
            pass
    update_progress(task_id, 60)

    # Google dork search
    try:
        r = requests.get(
            'https://www.google.com/search?q=' + quote(f'"{username}"'),
            headers={
                'User-Agent': ua.random,
                'Accept-Language': 'en-US,en;q=0.9',
            },
            timeout=10,
        )
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            links = []
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith('/url?q='):
                    url = href.split('/url?q=')[1].split('&')[0]
                    if username.lower() in url.lower():
                        links.append(url)
            if links:
                results['google_mentions'] = links[:10]
    except Exception:
        pass

    update_progress(task_id, 100)
    return results


# ═══════════════════════════════════════════════════════════════════════
# PHONE LOOKUP
# ═══════════════════════════════════════════════════════════════════════

def lookup_phone(phone, task_id):
    results = {}
    phone = phone.strip()
    update_progress(task_id, 10)

    try:
        if not phone.startswith('+'):
            phone = '+' + phone
        parsed = phonenumbers.parse(phone, None)
        if not phonenumbers.is_valid_number(parsed):
            return {'error': 'Invalid phone number. Use international format (e.g., +14155551234)'}

        results['parsed'] = {
            'international': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            'national': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            'e164': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            'country_code': parsed.country_code,
            'national_number': parsed.national_number,
        }
        results['country'] = pn_geocoder.description_for_number(parsed, 'en')
        results['carrier'] = pn_carrier.name_for_number(parsed, 'en')
        results['timezones'] = list(pn_timezone.time_zones_for_number(parsed))

        type_map = {
            0: 'FIXED_LINE', 1: 'MOBILE', 2: 'FIXED_LINE_OR_MOBILE',
            3: 'TOLL_FREE', 4: 'PREMIUM_RATE', 5: 'SHARED_COST',
            6: 'VOIP', 7: 'PERSONAL_NUMBER', 8: 'PAGER',
            9: 'UAN', 10: 'VOICEMAIL', 27: 'UNKNOWN',
        }
        results['number_type'] = type_map.get(phonenumbers.number_type(parsed), 'UNKNOWN')

    except phonenumbers.NumberParseException as e:
        return {'error': f'Failed to parse number: {str(e)}'}

    update_progress(task_id, 30)

    # Dehashed
    if Config.DEHASHED_EMAIL and Config.DEHASHED_API_KEY:
        try:
            e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            r = requests.get(
                f'https://api.dehashed.com/search?query=phone:{quote(e164)}',
                auth=(Config.DEHASHED_EMAIL, Config.DEHASHED_API_KEY),
                headers={'Accept': 'application/json'},
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get('total', 0) > 0:
                    results['dehashed'] = {
                        'total': data['total'],
                        'entries': [
                            {
                                'email': e.get('email'),
                                'name': e.get('name'),
                                'address': e.get('address'),
                                'database_name': e.get('database_name'),
                            }
                            for e in data.get('entries', [])[:15]
                        ],
                    }
        except Exception:
            pass
    update_progress(task_id, 50)

    # Google search
    try:
        r = requests.get(
            'https://www.google.com/search?q=' + quote(phone),
            headers={'User-Agent': ua.random, 'Accept-Language': 'en-US,en;q=0.9'},
            timeout=10,
        )
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            results['google_preview'] = soup.get_text()[:500]
    except Exception:
        pass

    update_progress(task_id, 100)
    return results


# ═══════════════════════════════════════════════════════════════════════
# DOMAIN LOOKUP
# ═══════════════════════════════════════════════════════════════════════

def lookup_domain(domain, task_id):
    results = {}
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain).split('/')[0]
    if not re.match(r'^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', domain):
        return {'error': 'Invalid domain format'}

    update_progress(task_id, 5)

    # DNS Records
    dns_records = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=10)
            dns_records[rtype] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            dns_records[rtype] = []
        except Exception:
            dns_records[rtype] = []
    results['dns_records'] = dns_records
    ips = dns_records.get('A', [])
    update_progress(task_id, 15)

    # WHOIS
    try:
        import whois as whois_lib
        w = whois_lib.whois(domain)
        results['whois'] = {
            'registrar': w.registrar,
            'creation_date': str(w.creation_date) if w.creation_date else None,
            'expiration_date': str(w.expiration_date) if w.expiration_date else None,
            'name_servers': w.name_servers if isinstance(w.name_servers, list) else [],
            'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
            'emails': w.emails if isinstance(w.emails, list) else [],
            'org': w.org,
            'country': w.country,
        }
    except Exception:
        results['whois'] = {'error': 'WHOIS lookup failed'}
    update_progress(task_id, 25)

    # VirusTotal
    if Config.VIRUSTOTAL_API_KEY:
        try:
            r = requests.get(
                f'https://www.virustotal.com/api/v3/domains/{domain}',
                headers={'x-apikey': Config.VIRUSTOTAL_API_KEY},
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json().get('data', {}).get('attributes', {})
                last_analysis = data.get('last_analysis_stats', {})
                results['virustotal'] = {
                    'malicious': last_analysis.get('malicious', 0),
                    'suspicious': last_analysis.get('suspicious', 0),
                    'harmless': last_analysis.get('harmless', 0),
                    'undetected': last_analysis.get('undetected', 0),
                    'categories': data.get('categories', {}),
                    'reputation': data.get('reputation'),
                }
        except Exception:
            pass
    update_progress(task_id, 35)

    # Security headers
    try:
        r = requests.get(f'https://{domain}', headers={'User-Agent': ua.random}, timeout=10)
        interesting = [
            'server', 'x-powered-by', 'x-frame-options',
            'content-security-policy', 'strict-transport-security',
            'x-content-type-options', 'x-xss-protection',
            'referrer-policy', 'permissions-policy',
            'set-cookie', 'x-robots-tag',
        ]
        headers_info = {h: r.headers[h] for h in interesting if h in r.headers}
        results['security_headers'] = headers_info
        results['http_status'] = r.status_code
        results['server_response_time_ms'] = round(r.elapsed.total_seconds() * 1000, 2)
    except Exception:
        results['security_headers'] = {'error': 'Could not connect'}
    update_progress(task_id, 45)

    # CRTSH subdomains
    try:
        r = requests.get(
            f'https://crt.sh/?q=%25.{domain}&output=json',
            headers={'User-Agent': ua.random},
            timeout=15,
        )
        if r.status_code == 200:
            entries = r.json()
            subdomains = set()
            for entry in entries:
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if sub.endswith(f'.{domain}') or sub == domain:
                        subdomains.add(sub)
            if subdomains:
                results['subdomains'] = sorted(subdomains)[:50]
    except Exception:
        pass
    update_progress(task_id, 55)

    # Wayback Machine
    try:
        r = requests.get(
            f'https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=30&fl=original,timestamp,statuscode',
            headers={'User-Agent': ua.random},
            timeout=15,
        )
        if r.status_code == 200 and len(r.json()) > 1:
            results['wayback'] = [
                {'url': item[0], 'date': item[1], 'status': item[2] if len(item) > 2 else 'unknown'}
                for item in r.json()[1:]
            ][:20]
    except Exception:
        pass
    update_progress(task_id, 65)

    # Tech detection
    try:
        r = requests.get(f'https://{domain}', headers={'User-Agent': ua.random}, timeout=10)
        html = r.text
        tech = []
        checks = {
            'WordPress': r'/wp-content|wp-includes|wordpress',
            'Joomla': r'/components|/modules|joomla',
            'Drupal': r'drupal|Drupal\.js',
            'Shopify': r'shopify\.com|/cdn/shop/',
            'Wix': r'Wix\.com|wixstatic',
            'Squarespace': r'squarespace\.com|squarespace',
            'Cloudflare': r'cloudflare|__cfduid',
            'nginx': r'nginx',
            'Apache': r'Apache',
            'PHP': r'PHP/',
            'Google Analytics': r'google-analytics\.com|ga\.js',
            'jQuery': r'jquery',
            'React': r'react\.js|__NEXT_DATA__',
            'Vue.js': r'vue\.js|__VUE__',
            'Bootstrap': r'bootstrap\.min\.css|bootstrap\.js',
            'FontAwesome': r'font-awesome|fontawesome',
        }
        for tech_name, pattern in checks.items():
            if re.search(pattern, html, re.IGNORECASE):
                tech.append(tech_name)
        if tech:
            results['technology'] = tech
    except Exception:
        pass
    update_progress(task_id, 75)

    # Port scan on main IP
    if ips:
        try:
            common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                           1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
                           8080, 8443, 9090, 27017]
            open_ports = []
            ip = ips[0]
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            if open_ports:
                results['open_ports'] = open_ports
        except Exception:
            pass
    update_progress(task_id, 85)

    # Zone transfer attempt
    try:
        ns_records = dns_records.get('NS', [])
        if ns_records:
            ns = str(ns_records[0]).rstrip('.')
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5, lifetime=10))
            if zone:
                results['zone_transfer'] = sorted([str(n) for n in zone.nodes.keys()])[:30]
    except Exception:
        pass

    update_progress(task_id, 100)
    return results


# ═══════════════════════════════════════════════════════════════════════
# IP LOOKUP
# ═══════════════════════════════════════════════════════════════════════

def lookup_ip(ip, task_id):
    results = {}
    ip = ip.strip()

    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return {'error': 'Invalid IPv4 format'}
    for octet in ip.split('.'):
        if not 0 <= int(octet) <= 255:
            return {'error': 'Octets must be 0-255'}

    update_progress(task_id, 10)

    # Reverse DNS
    try:
        results['hostname'] = socket.gethostbyaddr(ip)[0]
    except Exception:
        results['hostname'] = None

    # Geolocation
    try:
        r = requests.get(f'https://ipapi.co/{ip}/json/', headers={'User-Agent': ua.random}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            results['geo'] = {
                'ip': data.get('ip'),
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country_name'),
                'country_code': data.get('country_code'),
                'continent': data.get('continent_code'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'postal': data.get('postal'),
                'timezone': data.get('timezone'),
                'org': data.get('org'),
                'asn': data.get('asn'),
            }
    except Exception:
        pass
    update_progress(task_id, 25)

    # Fallback geo
    if 'geo' not in results:
        try:
            r = requests.get(f'https://ipwho.is/{ip}', headers={'User-Agent': ua.random}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                results['geo'] = {
                    'ip': data.get('ip'),
                    'city': data.get('city'),
                    'country': data.get('country'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'org': data.get('connection', {}).get('org'),
                    'asn': data.get('connection', {}).get('asn'),
                }
        except Exception:
            pass

    # Shodan
    if Config.SHODAN_API_KEY:
        try:
            r = requests.get(
                f'https://api.shodan.io/shodan/host/{ip}?key={Config.SHODAN_API_KEY}',
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                service_list = []
                for s in data.get('data', [])[:20]:
                    service_list.append({
                        'port': s.get('port'),
                        'service': s.get('service', ''),
                        'name': s.get('http', {}).get('title', ''),
                        'version': s.get('version', ''),
                    })
                results['shodan'] = {
                    'ports': data.get('ports', []),
                    'services': service_list,
                    'vulns': list(data.get('vulns', {}).keys()) if data.get('vulns') else [],
                    'org': data.get('org', ''),
                    'isp': data.get('isp', ''),
                    'os': data.get('os', ''),
                    'hostnames': data.get('hostnames', []),
                }
        except Exception:
            results['shodan'] = {'error': 'Shodan query failed or no data'}
    update_progress(task_id, 40)

    # VirusTotal
    if Config.VIRUSTOTAL_API_KEY:
        try:
            r = requests.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers={'x-apikey': Config.VIRUSTOTAL_API_KEY},
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json().get('data', {}).get('attributes', {})
                last_analysis = data.get('last_analysis_stats', {})
                results['virustotal'] = {
                    'malicious': last_analysis.get('malicious', 0),
                    'suspicious': last_analysis.get('suspicious', 0),
                    'harmless': last_analysis.get('harmless', 0),
                    'undetected': last_analysis.get('undetected', 0),
                }
        except Exception:
            pass
    update_progress(task_id, 55)

    # Port scan
    try:
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
            993, 995, 1433, 1521, 2049, 3306, 3389, 5060, 5432, 5900, 5985,
            5986, 6379, 8080, 8443, 9090, 27017,
        ]
        open_ports = []
        banners = {}
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    try:
                        sock.settimeout(2.0)
                        if port in [21, 22, 23, 25, 110, 143, 443, 993, 995, 8080, 8443]:
                            sock.sendall(b'\r\n')
                            banner = sock.recv(128).decode('utf-8', errors='ignore').strip()
                            if banner:
                                banners[str(port)] = banner[:120]
                    except Exception:
                        pass
                sock.close()
            except Exception:
                continue
        if open_ports:
            results['open_ports'] = open_ports
        if banners:
            results['banners'] = banners
    except Exception:
        pass
    update_progress(task_id, 70)

    # Reverse DNS via resolver
    try:
        answers = dns.resolver.resolve_address(ip, lifetime=5)
        results['reverse_dns'] = [str(a) for a in answers]
    except Exception:
        results['reverse_dns'] = []

    # RDAP lookup
    try:
        r = requests.get(
            f'https://rdap.arin.net/registry/ip/{ip}',
            headers={'Accept': 'application/json'},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            rdap_info = {
                'handle': data.get('handle'),
                'name': data.get('name'),
                'start_address': data.get('startAddress'),
                'end_address': data.get('endAddress'),
                'country': data.get('country'),
            }
            for entity in data.get('entities', []):
                vcards = entity.get('vcardArray', [[]])[1] if entity.get('vcardArray') else []
                for vcard in vcards:
                    if vcard[0] == 'fn' and len(vcard) > 3:
                        rdap_info['org_name'] = vcard[3]
                    if vcard[0] == 'email' and len(vcard) > 3:
                        rdap_info.setdefault('emails', []).append(vcard[3])
            results['rdap'] = rdap_info
    except Exception:
        pass
    update_progress(task_id, 85)

    # AbuseIPDB check
    try:
        r = requests.get(
            f'https://www.abuseipdb.com/check/{ip}',
            headers={'User-Agent': ua.random},
            timeout=10,
        )
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            conf = soup.find('span', class_='abuse-confidence')
            if conf:
                results['abuse_score'] = conf.get_text().strip()
    except Exception:
        pass

    update_progress(task_id, 100)
    return results
