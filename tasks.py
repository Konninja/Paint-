import time
import re
import hashlib
import socket
import threading
import json
import base64
from datetime import datetime
from urllib.parse import quote, urlparse

import requests
import dns.resolver
import dns.zone
import dns.query
import phonenumbers
from phonenumbers import carrier as pn_carrier, geocoder as pn_geocoder, timezone as pn_timezone
from fake_useragent import UserAgent
from bs4 import BeautifulSoup

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
            if task_id in tasks:
                tasks[task_id]['results'] = results
                tasks[task_id]['status'] = 'complete'
                tasks[task_id]['finished_at'] = datetime.utcnow().isoformat()
                tasks[task_id]['progress'] = 100
    except Exception as e:
        with tasks_lock:
            if task_id in tasks:
                tasks[task_id]['status'] = 'error'
                tasks[task_id]['error'] = str(e)
                tasks[task_id]['finished_at'] = datetime.utcnow().isoformat()


# ═══════════════════════════════════════════════════════════════════════
# SHARED HELPERS
# ═══════════════════════════════════════════════════════════════════════

def safe_request(url, headers=None, timeout=15, method='GET', **kwargs):
    """Safe HTTP request with proper UA, error handling."""
    try:
        if headers is None:
            headers = {'User-Agent': ua.random}
        else:
            headers.setdefault('User-Agent', ua.random)
        if method == 'GET':
            return requests.get(url, headers=headers, timeout=timeout, **kwargs)
        elif method == 'POST':
            return requests.post(url, headers=headers, timeout=timeout, **kwargs)
    except Exception:
        return None


# ─── API: Seon ────────────────────────────────────────────────────────
def seon_email_lookup(email):
    if not Config.SEON_API_KEY:
        return None
    try:
        r = requests.get(
            f'https://api.seon.io/SeonRestService/email-api/v1/{email}',
            headers={'X-API-Key': Config.SEON_API_KEY, 'User-Agent': ua.random},
            timeout=15
        )
        if r.status_code == 200:
            d = r.json()
            return {
                'data_breach': d.get('dataBreach'),
                'social_presence': d.get('socialPresence'),
                'blacklisted': d.get('blacklisted'),
                'domain_valid': d.get('domainValid'),
                'email_valid': d.get('emailValid'),
                'risk_score': d.get('riskScore'),
            }
    except Exception:
        return None


def seon_phone_lookup(phone):
    if not Config.SEON_API_KEY:
        return None
    try:
        r = requests.get(
            f'https://api.seon.io/SeonRestService/phone-api/v1/{phone}',
            headers={'X-API-Key': Config.SEON_API_KEY, 'User-Agent': ua.random},
            timeout=15
        )
        if r.status_code == 200:
            d = r.json()
            return {
                'valid': d.get('valid'),
                'country': d.get('country'),
                'carrier': d.get('carrier'),
                'line_type': d.get('lineType'),
                'risk_score': d.get('riskScore'),
            }
    except Exception:
        return None


# ─── API: Snusbase ────────────────────────────────────────────────────
def snusbase_lookup(query, query_type='email'):
    if not Config.SNUSBASE_API_KEY:
        return None
    try:
        r = requests.post(
            'https://api.snusbase.com/v1/search',
            headers={
                'Content-Type': 'application/json',
                'Auth': Config.SNUSBASE_API_KEY,
                'User-Agent': ua.random,
            },
            json={'type': query_type, 'query': query},
            timeout=30
        )
        return r.json() if r.status_code == 200 else {'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


def beta_snusbase_lookup(query, query_type='email'):
    if not Config.BETA_SNUSBASE_KEY:
        return None
    try:
        r = requests.post(
            'https://beta.snusbase.com/v1/search',
            headers={
                'Content-Type': 'application/json',
                'Auth': Config.BETA_SNUSBASE_KEY,
                'User-Agent': ua.random,
            },
            json={'type': query_type, 'query': query},
            timeout=30
        )
        return r.json() if r.status_code == 200 else {'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


# ─── API: LeakCheck ──────────────────────────────────────────────────
def leakcheck_lookup(query, query_type='email'):
    if not Config.LEAKCHECK_API_KEY:
        return None
    try:
        r = requests.get(
            f'https://leakcheck.io/api/v2/query?query={quote(query)}&type={query_type}',
            headers={
                'api-key': Config.LEAKCHECK_API_KEY,
                'User-Agent': ua.random,
                'Accept': 'application/json',
            },
            timeout=30
        )
        if r.status_code == 200:
            d = r.json()
            return d if d.get('success') else {'error': d.get('message', 'failed')}
        return {'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


# ─── API: Dehashed ────────────────────────────────────────────────────
def dehashed_lookup(query, query_type='email'):
    if not Config.DEHASHED_API_KEY or not Config.DEHASHED_EMAIL:
        return None
    try:
        auth = base64.b64encode(f'{Config.DEHASHED_EMAIL}:{Config.DEHASHED_API_KEY}'.encode()).decode()
        r = requests.get(
            f'https://api.dehashed.com/v1/search?query={query_type}:{quote(query)}&size=50',
            headers={'Authorization': f'Basic {auth}', 'Accept': 'application/json', 'User-Agent': ua.random},
            timeout=30
        )
        return r.json() if r.status_code == 200 else {'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


# ─── API: IntelX ──────────────────────────────────────────────────────
def intelx_lookup(query, query_type='email'):
    if not Config.INTELX_KEY:
        return None
    try:
        r = requests.get(
            f'https://2.intelx.io/phonebook/search?k={Config.INTELX_KEY}&t={quote(query)}',
            headers={'x-key': Config.INTELX_KEY, 'User-Agent': 'OsintSpectre/3.0', 'Accept': 'application/json'},
            timeout=20
        )
        return r.json() if r.status_code == 200 else {'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


# ─── API: IntelVault ──────────────────────────────────────────────────
def intelvault_lookup(query, query_type='email'):
    if not Config.INTELVAULT_KEY:
        return None
    try:
        r = requests.get(
            f'https://intelvault.com/api/v1/{query_type}/{quote(query)}',
            headers={'Authorization': f'Bearer {Config.INTELVAULT_KEY}', 'User-Agent': ua.random},
            timeout=20
        )
        return r.json() if r.status_code == 200 else {'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


# ─── API: OSINT Cat ──────────────────────────────────────────────────
def osintcat_lookup(query, query_type='email'):
    if not Config.OSINTCAT_KEY1:
        return None
    try:
        r = requests.post(
            'https://osintcat.ru/api/v1/search',
            headers={
                'Authorization': f'Bearer {Config.OSINTCAT_KEY1}',
                'X-API-Key': Config.OSINTCAT_KEY2,
                'User-Agent': ua.random,
                'Content-Type': 'application/json',
            },
            json={
                'type': query_type,
                'query': query,
                'sources': ['snusbase', 'leakcheck', 'hackcheck', 'intelvault'],
            },
            timeout=30
        )
        return r.json() if r.status_code == 200 else {'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


# ─── API: CSINT.tools ────────────────────────────────────────────────
def csint_tools_lookup(query, query_type='email'):
    if not Config.CSINT_TOOLS_KEY1:
        return None
    try:
        r = requests.get(
            f'https://csint.tools/api/v1/{query_type}/{quote(query)}',
            headers={
                'X-API-Key': Config.CSINT_TOOLS_KEY1,
                'X-API-Key-2': Config.CSINT_TOOLS_KEY2,
                'User-Agent': ua.random,
            },
            timeout=20
        )
        return r.json() if r.status_code == 200 else {'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


# ─── API: Tracked.sh ──────────────────────────────────────────────────
def tracked_sh_lookup(query, query_type='email'):
    if not Config.TRACKED_SH_KEY1:
        return None
    try:
        r = requests.get(
            f'https://tracked.sh/api/v1/{query_type}/{quote(query)}',
            headers={
                'x-api-key': Config.TRACKED_SH_KEY1,
                'x-api-secret': Config.TRACKED_SH_KEY2,
                'User-Agent': ua.random,
            },
            timeout=20
        )
        return r.json() if r.status_code == 200 else {'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


# ─── API: Source.red ──────────────────────────────────────────────────
def source_red_lookup(query, query_type='email'):
    if not Config.SOURCE_RED_KEY:
        return None
    try:
        r = requests.get(
            f'https://source.red/api/v1/{query_type}/{quote(query)}',
            headers={'Authorization': f'Bearer {Config.SOURCE_RED_KEY}', 'User-Agent': ua.random},
            timeout=20
        )
        return r.json() if r.status_code == 200 else {'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


# ─── API: OSINTWave.rip ──────────────────────────────────────────────
def osintwave_lookup(query, query_type='email'):
    if not Config.OSINTWAVE_KEY:
        return None
    try:
        r = requests.get(
            f'https://osintwave.rip/api/v1/{query_type}/{quote(query)}',
            headers={'Authorization': f'Bearer {Config.OSINTWAVE_KEY}', 'User-Agent': ua.random},
            timeout=20
        )
        return r.json() if r.status_code == 200 else {'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'error': str(e)}


# ─── HIBP Check ──────────────────────────────────────────────────────
def hibp_check(email):
    try:
        sha1 = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        r = requests.get(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            headers={'User-Agent': 'OsintSpectre/3.0'},
            timeout=10
        )
        if r.status_code == 200:
            for line in r.text.splitlines():
                if line.startswith(suffix):
                    count = int(line.split(':')[1].strip())
                    return {'pwned': True, 'breach_count': count}
            return {'pwned': False, 'breach_count': 0}
    except Exception:
        return None


# ─── Scraper: GoLookup Phone ─────────────────────────────────────────
def golookup_phone(phone):
    try:
        r = safe_request(f'https://www.golookup.com/phone/{quote(phone)}', timeout=15)
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            result = {}
            name_tag = soup.find('h1', class_='name') or soup.find('div', class_='person-name')
            if name_tag:
                result['name'] = name_tag.get_text(strip=True)
            loc_tags = soup.find_all('div', class_='location')
            if loc_tags:
                result['location'] = loc_tags[0].get_text(strip=True)
            carrier_tag = soup.find('span', class_='carrier')
            if carrier_tag:
                result['carrier'] = carrier_tag.get_text(strip=True)
            rows = soup.find_all('tr')
            for row in rows:
                cells = row.find_all('td')
                if len(cells) >= 2:
                    key = cells[0].get_text(strip=True).lower()
                    val = cells[1].get_text(strip=True)
                    if 'name' in key: result['name'] = val
                    elif 'location' in key or 'city' in key: result['location'] = val
                    elif 'carrier' in key or 'provider' in key: result['carrier'] = val
            return result if result else {'note': 'page loaded, minimal data'}
        return {'error': f'HTTP {r.status_code}' if r else 'no response'}
    except Exception as e:
        return {'error': str(e)}


# ─── Scraper: CallerID Test ──────────────────────────────────────────
def callerid_test(phone):
    try:
        r = safe_request(f'https://calleridtest.com/{quote(phone.lstrip("+"))}', timeout=10)
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            result = {}
            for cls in ['carrier', 'provider']:
                el = soup.find('div', class_=cls) or soup.find('span', class_=cls)
                if el: result['carrier'] = el.get_text(strip=True); break
            loc = soup.find('div', class_='location')
            if loc: result['location'] = loc.get_text(strip=True)
            return result if result else None
    except Exception:
        return None


# ─── Scraper: PhoneInfo.io ───────────────────────────────────────────
def phoneinfo_io(phone):
    try:
        r = safe_request(f'https://phoneinfo.io/phone/{quote(phone.lstrip("+"))}', timeout=10)
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            result = {}
            for row in soup.find_all('div', class_='info-row') or soup.find_all('tr'):
                txt = row.get_text(strip=True)
                if 'Carrier' in txt or 'Provider' in txt:
                    result['carrier'] = txt.split(':')[-1].strip() if ':' in txt else txt
                if 'Location' in txt or 'City' in txt:
                    result['location'] = txt.split(':')[-1].strip() if ':' in txt else txt
                if 'Line' in txt and 'Type' in txt:
                    result['line_type'] = txt.split(':')[-1].strip() if ':' in txt else txt
            return result if result else None
    except Exception:
        return None


# ─── Scraper: Thatsthem ──────────────────────────────────────────────
def thatsthem_lookup(query, query_type='name'):
    search_urls = {
        'name': f'https://thatsthem.com/name/{quote(query.replace(" ", "-"))}',
        'phone': f'https://thatsthem.com/phone/{quote(query.lstrip("+"))}',
        'email': f'https://thatsthem.com/email/{quote(query)}',
        'address': f'https://thatsthem.com/address/{quote(query)}',
    }
    url = search_urls.get(query_type, search_urls['name'])
    try:
        r = safe_request(url, timeout=15)
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            result = {'profiles': []}
            for item in (soup.find_all('div', class_='result') or soup.find_all('div', class_='card') or []):
                name_tag = item.find('h3') or item.find('a', class_='name')
                info = {}
                if name_tag: info['name'] = name_tag.get_text(strip=True)
                for dt in item.find_all(['div', 'p']):
                    txt = dt.get_text(strip=True)
                    if '@' in txt: info['email'] = txt
                    elif re.match(r'\(\d{3}\)', txt) or re.match(r'\d{3}-\d{3}', txt): info['phone'] = txt
                    elif re.search(r'\d+\s+\w+', txt) and len(txt) > 10: info['address'] = txt
                    elif 'age' in txt.lower() or 'born' in txt.lower(): info['age'] = txt
                if info.get('name'): result['profiles'].append(info)
            result['profile_count'] = len(result['profiles'])
            return result
    except Exception:
        return None


# ─── Scraper: FastPeopleSearch ───────────────────────────────────────
def fastpeoplesearch_lookup(query, query_type='phone'):
    try:
        r = safe_request(f'https://www.fastpeoplesearch.com/{query_type}/{quote(query)}', timeout=15)
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            result = {'results': []}
            for card in soup.find_all('div', class_='card') or soup.find_all('div', class_='result-item'):
                info = {}
                for line in card.get_text(separator='\n').split('\n'):
                    line = line.strip()
                    if re.match(r'^[A-Z][a-z]+ [A-Z][a-z]+', line) and len(line.split()) <= 4:
                        info['name'] = line
                    elif re.match(r'\(\d{3}\)', line): info['phone'] = line
                    elif '@' in line: info['email'] = line
                    elif re.search(r'\d+\s+\w+', line) and len(line) > 15: info['address'] = line
                if info: result['results'].append(info)
            return result
    except Exception:
        return None


# ─── Whitepages Scraper ─────────────────────────────────────────────
def whitepages_lookup(query, query_type='phone'):
    try:
        r = safe_request(f'https://www.whitepages.com/{query_type}/{quote(query.lstrip("+"))}', timeout=15)
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            result = {}
            name = soup.find('h1', class_='name') or soup.find('div', class_='name')
            if name: result['name'] = name.get_text(strip=True)
            addr = soup.find('div', class_='address') or soup.find('span', class_='location')
            if addr: result['address'] = addr.get_text(strip=True)
            age = soup.find('span', class_='age')
            if age: result['age'] = age.get_text(strip=True)
            return result if result else None
    except Exception:
        return None


# ─── Social Media Email Checker (Holehe-style) ──────────────────────
def check_social_media_by_email(email):
    """Check ~30 platforms for account registration by email."""
    domains = {
        'github':     f'https://github.com/search?q={quote(email)}&type=users',
        'twitter':    f'https://twitter.com/i/users/email_available.json?email={quote(email)}',
        'instagram':  f'https://www.instagram.com/accounts/account_recovery_send_email/',
        'spotify':    f'https://www.spotify.com/api/signup/validate',
        'adobe':      f'https://auth.services.adobe.com/signup/v2/users/email/{quote(email)}',
        'gravatar':   f'https://www.gravatar.com/{hashlib.md5(email.lower().strip().encode()).hexdigest()}',
        'pinterest':  f'https://www.pinterest.com/resource/EmailExistsResource/get/',
        'lastfm':     f'https://www.last.fm/join/validate/email',
        'wordpress':  f'https://public-api.wordpress.com/rest/v1/users/email/exists?email={quote(email)}',
        'snapchat':   f'https://accounts.snapchat.com/accounts/merlin/validate_email',
    }
    results = {}
    for platform, url in domains.items():
        try:
            r = safe_request(url, timeout=8)
            if r:
                results[platform] = {'status_code': r.status_code, 'found': r.status_code == 200}
        except Exception:
            pass
    return results


# ─── SSN Area Number Decoder (via SteveMorse) ───────────────────────
def ssn_area_lookup(state, year_of_birth):
    """Decode SSN area number from state + year of birth."""
    try:
        r = safe_request(
            f'https://stevemorse.org/ssn/ssn.php?state={quote(state)}&year={year_of_birth}&go=Lookup',
            timeout=10
        )
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            result = {}
            table = soup.find('table')
            if table:
                rows = table.find_all('tr')
                data = []
                for row in rows[1:]:
                    cells = row.find_all('td')
                    if len(cells) >= 2:
                        data.append({
                            'area': cells[0].get_text(strip=True),
                            'state': cells[1].get_text(strip=True),
                        })
                result['area_numbers'] = data
            return result
    except Exception:
        return None


# ─── DL Format Lookup (via HighProgrammer) ──────────────────────────
def dl_format_lookup(state):
    """Lookup driver's license number format for a US state."""
    try:
        r = safe_request(f'https://highprogrammer.com/cgi-bin/duidinfo/?state={quote(state)}', timeout=10)
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            result = {}
            pre = soup.find('pre')
            if pre:
                result['format'] = pre.get_text(strip=True)
            return result
    except Exception:
        return None


# ─── JudyRecords (Criminal Records) ─────────────────────────────────
def judyrecords_lookup(name):
    """Search judyrecords.com for criminal records."""
    try:
        r = safe_request(
            f'https://www.judyrecords.com/search?q={quote(name)}',
            timeout=15
        )
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            results = {'cases': []}
            for row in soup.find_all('tr')[1:15]:
                cells = row.find_all('td')
                if len(cells) >= 3:
                    results['cases'].append({
                        'case_number': cells[0].get_text(strip=True) if cells[0] else '',
                        'court': cells[1].get_text(strip=True) if len(cells) > 1 else '',
                        'type': cells[2].get_text(strip=True) if len(cells) > 2 else '',
                    })
            return results
    except Exception:
        return None


# ─── US Courts Search ────────────────────────────────────────────────
def uscourts_lookup(name):
    """Search US courts for bankruptcy, civil, criminal cases via PACER."""
    try:
        r = safe_request(
            f'https://pcl.uscourts.gov/search?query={quote(name)}',
            timeout=15
        )
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            results = {'records': []}
            for item in soup.find_all('div', class_='result-item')[:10]:
                results['records'].append(item.get_text(strip=True))
            return results
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════
# EMAIL LOOKUP
# ═══════════════════════════════════════════════════════════════════════

def lookup_email(email, task_id):
    results = {}
    update_progress(task_id, 5)

    domain = email.split('@')[1]

    # 1. Hunter.io email verification
    if Config.HUNTER_API_KEY:
        try:
            r = requests.get(
                f'https://api.hunter.io/v2/email-verifier?email={email}&api_key={Config.HUNTER_API_KEY}',
                timeout=10
            )
            if r.status_code == 200:
                d = r.json().get('data', {})
                results['hunter'] = {
                    'status': d.get('status'),
                    'score': d.get('score'),
                    'disposable': d.get('disposable'),
                    'webmail': d.get('webmail'),
                    'mx_records': d.get('mx_records'),
                    'smtp_server': d.get('smtp_server'),
                    'first_name': d.get('firstname'),
                    'last_name': d.get('lastname'),
                }
                rd = safe_request(
                    f'https://api.hunter.io/v2/domain-information?domain={domain}&api_key={Config.HUNTER_API_KEY}',
                    timeout=10
                )
                if rd and rd.status_code == 200:
                    od = rd.json().get('data', {})
                    results['hunter']['organization'] = od.get('organization')
                    results['hunter']['industry'] = od.get('industry')
        except Exception:
            pass
    update_progress(task_id, 12)

    # 2. Seon
    seon = seon_email_lookup(email)
    if seon: results['seon'] = seon
    update_progress(task_id, 18)

    # 3. HIBP
    hibp = hibp_check(email)
    if hibp: results['hibp'] = hibp
    update_progress(task_id, 22)

    # 4. Breach databases (parallel)
    br = {}
    threads = []

    def q_snusbase(): br['snusbase'] = snusbase_lookup(email, 'email')
    def q_beta(): br['beta_snusbase'] = beta_snusbase_lookup(email, 'email')
    def q_leakcheck(): br['leakcheck'] = leakcheck_lookup(email, 'email')
    def q_dehashed(): br['dehashed'] = dehashed_lookup(email, 'email')
    def q_osintcat(): br['osintcat'] = osintcat_lookup(email, 'email')
    def q_intelvault(): br['intelvault'] = intelvault_lookup(email, 'email')
    def q_intelx(): br['intelx'] = intelx_lookup(email, 'email')
    def q_csint(): br['csint_tools'] = csint_tools_lookup(email, 'email')
    def q_tracked(): br['tracked_sh'] = tracked_sh_lookup(email, 'email')
    def q_sourcered(): br['source_red'] = source_red_lookup(email, 'email')
    def q_osintwave(): br['osintwave'] = osintwave_lookup(email, 'email')

    for fn in [q_snusbase, q_beta, q_leakcheck, q_dehashed, q_osintcat,
               q_intelvault, q_intelx, q_csint, q_tracked, q_sourcered, q_osintwave]:
        t = threading.Thread(target=fn, daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=25)

    # Filter out None/error results
    breach_results = {}
    for k, v in br.items():
        if v and not isinstance(v, dict) or (isinstance(v, dict) and 'error' not in v):
            breach_results[k] = v
    if breach_results:
        results['breach_databases'] = breach_results
    update_progress(task_id, 35)

    # 5. Thatsthem email search
    thatsthem = thatsthem_lookup(email, 'email')
    if thatsthem: results['thatsthem'] = thatsthem
    update_progress(task_id, 40)

    # 6. Google dork search for the email
    try:
        r = safe_request(
            f'https://www.google.com/search?q={quote(email)}',
            timeout=10
        )
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            links = []
            for a in soup.find_all('a', href=True)[:10]:
                href = a['href']
                if href.startswith('/url?q='):
                    url = href.split('/url?q=')[1].split('&')[0]
                    if email.split('@')[1] not in url and not url.startswith('http'): continue
                    links.append(url)
            if links: results['google_dorks'] = links
    except Exception:
        pass
    update_progress(task_id, 50)

    # 7. Social media presence check
    try:
        social = check_social_media_by_email(email)
        if social: results['social_media'] = social
    except Exception:
        pass
    update_progress(task_id, 60)

    # 8. Gravatar
    try:
        grav_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
        gr = safe_request(f'https://www.gravatar.com/{grav_hash}.json', timeout=8)
        if gr and gr.status_code == 200:
            gd = gr.json().get('entry', [{}])[0]
            results['gravatar'] = {
                'profile_url': f'https://www.gravatar.com/{grav_hash}',
                'display_name': gd.get('displayName'),
                'preferred_username': gd.get('preferredUsername'),
                'about': gd.get('about'),
                'accounts': gd.get('accounts', []),
            }
    except Exception:
        pass
    update_progress(task_id, 65)

    # 9. MX records
    try:
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=5)
        results['mx_records'] = [str(mx.exchange) for mx in mx_records][:10]
    except Exception:
        pass

    # 10. SPF/DMARC records
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        spf = [str(t) for t in txt_records if 'v=spf1' in str(t)]
        if spf: results['spf_record'] = spf[0]
    except Exception:
        pass
    try:
        dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=5)
        results['dmarc_record'] = str(dmarc[0])
    except Exception:
        pass
    update_progress(task_id, 70)

    # 11. Hunter.io domain info (already did this above inside hunter block if possible)

    # 12. EmailRep
    try:
        er = safe_request(f'https://emailrep.io/{quote(email)}', timeout=10)
        if er and er.status_code == 200:
            ed = er.json()
            results['emailrep'] = {
                'reputation': ed.get('reputation'),
                'suspicious': ed.get('suspicious'),
                'blacklisted': ed.get('details', {}).get('blacklisted'),
                'malicious_activity': ed.get('details', {}).get('malicious_activity'),
                'spam': ed.get('details', {}).get('spam'),
            }
    except Exception:
        pass
    update_progress(task_id, 80)

    return results


# ═══════════════════════════════════════════════════════════════════════
# USERNAME LOOKUP
# ═══════════════════════════════════════════════════════════════════════

def check_username_on_platform(username, platform_url_template, platform_name):
    """Check if username exists on a social platform."""
    try:
        url = platform_url_template.format(username=username)
        r = safe_request(url, timeout=8)
        if r:
            if r.status_code == 200:
                return {'platform': platform_name, 'exists': True, 'profile_url': url}
            elif r.status_code == 404:
                return {'platform': platform_name, 'exists': False}
            else:
                return {'platform': platform_name, 'exists': None, 'status_code': r.status_code}
    except Exception:
        return {'platform': platform_name, 'exists': None, 'error': 'connection_failed'}
    return {'platform': platform_name, 'exists': None}


def lookup_username(username, task_id):
    results = {}
    update_progress(task_id, 5)

    platforms = [
        ('github', 'https://github.com/{username}'),
        ('twitter', 'https://twitter.com/{username}'),
        ('instagram', 'https://www.instagram.com/{username}/'),
        ('facebook', 'https://www.facebook.com/{username}'),
        ('linkedin', 'https://www.linkedin.com/in/{username}'),
        ('reddit', 'https://www.reddit.com/user/{username}'),
        ('youtube', 'https://www.youtube.com/@{username}'),
        ('tiktok', 'https://www.tiktok.com/@{username}'),
        ('snapchat', 'https://www.snapchat.com/add/{username}'),
        ('pinterest', 'https://www.pinterest.com/{username}'),
        ('tumblr', 'https://{username}.tumblr.com'),
        ('medium', 'https://medium.com/@{username}'),
        ('devto', 'https://dev.to/{username}'),
        ('hackernews', 'https://news.ycombinator.com/user?id={username}'),
        ('keybase', 'https://keybase.io/{username}'),
        ('telegram', 'https://t.me/{username}'),
        ('whatsapp', 'https://wa.me/{username}'),
        ('twitch', 'https://www.twitch.tv/{username}'),
        ('discord', 'https://discord.com/users/{username}'),
        ('steam', 'https://steamcommunity.com/id/{username}'),
        ('patreon', 'https://www.patreon.com/{username}'),
        ('bitbucket', 'https://bitbucket.org/{username}'),
        ('gitlab', 'https://gitlab.com/{username}'),
        ('flickr', 'https://www.flickr.com/people/{username}'),
        ('behance', 'https://www.behance.net/{username}'),
        ('dribbble', 'https://dribbble.com/{username}'),
        ('aboutme', 'https://about.me/{username}'),
        ('angelco', 'https://angel.co/u/{username}'),
        ('producthunt', 'https://www.producthunt.com/@{username}'),
        ('mastodon.social', 'https://mastodon.social/@{username}'),
        ('pleroma', 'https://pleroma.site/users/{username}'),
        ('vk', 'https://vk.com/{username}'),
        ('ok', 'https://ok.ru/{username}'),
        ('weibo', 'https://weibo.com/{username}'),
        ('xing', 'https://www.xing.com/profile/{username}'),
        ('slideshare', 'https://www.slideshare.net/{username}'),
        ('replit', 'https://replit.com/@{username}'),
        ('codepen', 'https://codepen.io/{username}'),
        ('hackaday', 'https://hackaday.io/{username}'),
        ('hackerone', 'https://hackerone.com/{username}'),
        ('bugcrowd', 'https://bugcrowd.com/{username}'),
        ('tryhackme', 'https://tryhackme.com/p/{username}'),
        ('hackthebox', 'https://forum.hackthebox.com/u/{username}'),
        ('ctftime', 'https://ctftime.org/team/{username}'),
        ('pastebin', 'https://pastebin.com/u/{username}'),
        ('gist', 'https://gist.github.com/{username}'),
    ]

    results['platforms'] = []
    checked = 0
    for platform_name, url_template in platforms:
        res = check_username_on_platform(username, url_template, platform_name)
        results['platforms'].append(res)
        checked += 1
        if checked % 10 == 0:
            pct = 5 + int((checked / len(platforms)) * 60)
            update_progress(task_id, pct)
    update_progress(task_id, 65)

    found = [p for p in results['platforms'] if p.get('exists')]
    results['found_count'] = len(found)
    results['found_profiles'] = [p for p in found[:20]]

    # 2. Snusbase username lookup
    br = {}

    def q_snusbase_usr(): br['snusbase'] = snusbase_lookup(username, 'username')
    def q_beta_usr(): br['beta_snusbase'] = beta_snusbase_lookup(username, 'username')
    def q_leakcheck_usr(): br['leakcheck'] = leakcheck_lookup(username, 'username')
    def q_dehashed_usr(): br['dehashed'] = dehashed_lookup(username, 'username')
    def q_csint_usr(): br['csint_tools'] = csint_tools_lookup(username, 'username')
    def q_osintwave_usr(): br['osintwave'] = osintwave_lookup(username, 'username')

    threads = []
    for fn in [q_snusbase_usr, q_beta_usr, q_leakcheck_usr, q_dehashed_usr, q_csint_usr, q_osintwave_usr]:
        t = threading.Thread(target=fn, daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=20)

    breach_results = {}
    for k, v in br.items():
        if v and (not isinstance(v, dict) or 'error' not in v):
            breach_results[k] = v
    if breach_results:
        results['breach_databases'] = breach_results
    update_progress(task_id, 80)

    # 3. Google search
    try:
        r = safe_request(
            f'https://www.google.com/search?q={quote(username)}',
            timeout=10
        )
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            links = []
            for a in soup.find_all('a', href=True)[:10]:
                href = a['href']
                if href.startswith('/url?q='):
                    url = href.split('/url?q=')[1].split('&')[0]
                    links.append(url)
            if links: results['google_results'] = links
    except Exception:
        pass
    update_progress(task_id, 90)

    return results


# ═══════════════════════════════════════════════════════════════════════
# PHONE LOOKUP
# ═══════════════════════════════════════════════════════════════════════

def lookup_phone(phone, task_id):
    results = {}
    update_progress(task_id, 5)

    # 1. Parse phone number
    try:
        pn = phonenumbers.parse(phone, None)
        results['parsed'] = {
            'international': phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            'national': phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL),
            'e164': phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164),
            'country_code': pn.country_code,
            'national_number': pn.national_number,
            'valid': phonenumbers.is_valid_number(pn),
            'possible': phonenumbers.is_possible_number(pn),
            'country': pn_geocoder.description_for_number(pn, 'en'),
            'carrier': pn_carrier.name_for_number(pn, 'en'),
            'timezones': pn_timezone.time_zones_for_number(pn),
            'type': 'mobile' if phonenumbers.number_type(pn) == 1 else 'fixed' if phonenumbers.number_type(pn) == 0 else 'other',
        }
    except Exception as e:
        results['parsed'] = {'error': str(e)}
    update_progress(task_id, 12)

    # 2. Seon
    seon = seon_phone_lookup(phone)
    if seon: results['seon'] = seon
    update_progress(task_id, 18)

    # 3. GoLookup
    golookup = golookup_phone(phone)
    if golookup: results['golookup'] = golookup
    update_progress(task_id, 25)

    # 4. CallerID Test
    callerid = callerid_test(phone)
    if callerid: results['callerid_test'] = callerid
    update_progress(task_id, 30)

    # 5. PhoneInfo.io
    phoneinfo = phoneinfo_io(phone)
    if phoneinfo: results['phoneinfo'] = phoneinfo
    update_progress(task_id, 35)

    # 6. Breach databases (parallel)
    br = {}
    threads = []

    def q_snusbase(): br['snusbase'] = snusbase_lookup(phone, 'phone')
    def q_beta(): br['beta_snusbase'] = beta_snusbase_lookup(phone, 'phone')
    def q_leakcheck(): br['leakcheck'] = leakcheck_lookup(phone, 'phone')
    def q_dehashed(): br['dehashed'] = dehashed_lookup(phone, 'phone')

    for fn in [q_snusbase, q_beta, q_leakcheck, q_dehashed]:
        t = threading.Thread(target=fn, daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=20)
    breach_results = {}
    for k, v in br.items():
        if v and (not isinstance(v, dict) or 'error' not in v):
            breach_results[k] = v
    if breach_results:
        results['breach_databases'] = breach_results
    update_progress(task_id, 45)

    # 7. Thatsthem
    thatsthem = thatsthem_lookup(phone, 'phone')
    if thatsthem: results['thatsthem'] = thatsthem
    update_progress(task_id, 50)

    # 8. Whitepages
    wp = whitepages_lookup(phone, 'phone')
    if wp: results['whitepages'] = wp
    update_progress(task_id, 55)

    # 9. FastPeopleSearch
    fps = fastpeoplesearch_lookup(phone, 'phone')
    if fps: results['fastpeoplesearch'] = fps
    update_progress(task_id, 60)

    # 10. Google search
    try:
        r = safe_request(
            f'https://www.google.com/search?q={quote(phone)}',
            timeout=10
        )
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'lxml')
            links = []
            for a in soup.find_all('a', href=True)[:10]:
                href = a['href']
                if href.startswith('/url?q='):
                    url = href.split('/url?q=')[1].split('&')[0]
                    links.append(url)
            if links: results['google_results'] = links
    except Exception:
        pass
    update_progress(task_id, 70)

    return results


# ═══════════════════════════════════════════════════════════════════════
# DOMAIN LOOKUP
# ═══════════════════════════════════════════════════════════════════════

def lookup_domain(domain, task_id):
    results = {}
    update_progress(task_id, 5)

    # 1. WHOIS
    try:
        r = safe_request(f'https://whois.arin.net/rest/domain/{domain}', timeout=10)
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, 'xml')
            d = {}
            for tag in ['name', 'handle', 'registrationDate', 'expirationDate', 'lastChangedDate']:
                el = soup.find(tag)
                if el: d[tag] = el.get_text(strip=True)
            nameservers = soup.find_all('nameServer')
            if nameservers: d['nameservers'] = [ns.get_text(strip=True) for ns in nameservers[:10]]
            results['whois'] = d
    except Exception:
        pass
    update_progress(task_id, 15)

    # 2. DNS records
    records = {}
    for rec_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV']:
        try:
            ans = dns.resolver.resolve(domain, rec_type, lifetime=5)
            records[rec_type] = [str(r) for r in ans][:10]
        except Exception:
            pass
    if records:
        results['dns_records'] = records
    update_progress(task_id, 25)

    # 3. IP address resolution
    try:
        ips = dns.resolver.resolve(domain, 'A', lifetime=5)
        results['ip_addresses'] = [str(r) for r in ips][:5]
    except Exception:
        pass
    update_progress(task_id, 30)

    # 4. Subdomain enumeration via DNS zone transfer attempt
    try:
        ns_records = dns.resolver.resolve(domain, 'NS', lifetime=5)
        for ns in ns_records[:3]:
            ns_str = str(ns)
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns_str, domain, lifetime=10))
                if z:
                    results['zone_transfer'] = {
                        'nameserver': ns_str,
                        'records': [str(k) for k in z.nodes.keys()][:50],
                        'success': True,
                    }
                    break
            except Exception:
                continue
    except Exception:
        pass
    update_progress(task_id, 40)

    # 5. VirusTotal domain report
    if Config.VIRUSTOTAL_API_KEY:
        try:
            r = requests.get(
                f'https://www.virustotal.com/api/v3/domains/{domain}',
                headers={'x-apikey': Config.VIRUSTOTAL_API_KEY},
                timeout=15
            )
            if r.status_code == 200:
                d = r.json().get('data', {}).get('attributes', {})
                results['virustotal'] = {
                    'last_analysis_stats': d.get('last_analysis_stats', {}),
                    'categories': {k: v for k, v in d.get('categories', {}).items() if v},
                    'popularity_ranks': d.get('popularity_ranks', {}),
                }
        except Exception:
            pass
    update_progress(task_id, 50)

    # 6. WhatCMS
    if Config.WHATCMS_API_KEY:
        try:
            r = requests.get(
                f'https://whatcms.org/APIEndpoint?key={Config.WHATCMS_API_KEY}&url={domain}',
                timeout=15
            )
            if r.status_code == 200:
                d = r.json().get('result', {})
                results['whatcms'] = {
                    'cms': d.get('name'),
                    'version': d.get('version'),
                    'confidence': d.get('confidence'),
                    'cms_url': d.get('url'),
                }
        except Exception:
            pass
    update_progress(task_id, 60)

    # 7. Security headers
    try:
        for scheme in ['https', 'http']:
            r = safe_request(f'{scheme}://{domain}', timeout=10)
            if r:
                headers = dict(r.headers)
                interesting = ['server', 'x-powered-by', 'x-frame-options',
                              'content-security-policy', 'strict-transport-security',
                              'x-content-type-options', 'x-xss-protection',
                              'set-cookie', 'www-authenticate', 'location']
                header_info = {k: headers[k] for k in interesting if k in headers}
                if header_info:
                    results[f'{scheme}_headers'] = header_info
                    results['response_code'] = r.status_code
                break
    except Exception:
        pass
    update_progress(task_id, 70)

    # 8. SSL certificate info
    try:
        import ssl
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            if cert:
                results['ssl'] = {
                    'subject': dict(cert.get('subject', [])),
                    'issuer': dict(cert.get('issuer', [])),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'serial': cert.get('serialNumber'),
                    'san': cert.get('subjectAltName', []),
                }
    except Exception:
        pass
    update_progress(task_id, 80)

    # 9. Wayback Machine
    try:
        r = safe_request(f'http://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=10', timeout=10)
        if r and r.status_code == 200 and len(r.json()) > 1:
            snapshots = []
            for row in r.json()[1:11]:
                if len(row) >= 6:
                    snapshots.append({
                        'timestamp': row[1],
                        'original': row[2],
                        'status': row[4],
                    })
            if snapshots: results['wayback_snapshots'] = snapshots
    except Exception:
        pass
    update_progress(task_id, 90)

    # 10. Shodan for domain
    if Config.SHODAN_API_KEY:
        try:
            r = requests.get(
                f'https://api.shodan.io/shodan/host/search?key={Config.SHODAN_API_KEY}&query=hostname:{domain}',
                timeout=15
            )
            if r.status_code == 200:
                d = r.json()
                if d.get('total', 0) > 0:
                    results['shodan'] = {
                        'total_results': d['total'],
                        'matches': [{'ip': m.get('ip_str'), 'port': m.get('port'), 'org': m.get('org')}
                                    for m in d.get('matches', [])[:10]],
                    }
        except Exception:
            pass
    update_progress(task_id, 95)

    return results


# ═══════════════════════════════════════════════════════════════════════
# IP LOOKUP (Preserved from original + enhanced)
# ═══════════════════════════════════════════════════════════════════════

def lookup_ip(ip, task_id):
    results = {}
    update_progress(task_id, 5)

    # Geo (ipapi.co)
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
