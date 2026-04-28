import hashlib
import time
import threading
import logging
from datetime import datetime

from flask import Flask, render_template, request, jsonify, make_response
from functools import wraps

from config import Config
from tasks import background_lookup, get_task, tasks, tasks_lock

# ─── Logging ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
logger = logging.getLogger(__name__)

# ─── App Factory ──────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.config['DEBUG'] = Config.DEBUG

# ─── Rate Limiter ─────────────────────────────────────────────────────
rate_limit_store = {}
rate_limit_lock = threading.Lock()


def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr or 'unknown'
        now = time.time()
        with rate_limit_lock:
            if ip in rate_limit_store:
                window_start, count = rate_limit_store[ip]
                if now - window_start > Config.RATE_LIMIT_WINDOW:
                    rate_limit_store[ip] = (now, 1)
                elif count >= Config.RATE_LIMIT_REQUESTS:
                    resp = jsonify({'error': 'Rate limit exceeded. Try again shortly.'})
                    resp.status_code = 429
                    return resp
                else:
                    rate_limit_store[ip] = (window_start, count + 1)
            else:
                rate_limit_store[ip] = (now, 1)
        return f(*args, **kwargs)
    return decorated


# ─── Cleanup stale tasks ──────────────────────────────────────────────
def cleanup_stale_tasks():
    while True:
        time.sleep(60)
        now = datetime.utcnow()
        with tasks_lock:
            stale = []
            for tid, task in tasks.items():
                if task.get('finished_at'):
                    finished = datetime.fromisoformat(task['finished_at'])
                    if (now - finished).total_seconds() > 1800:
                        stale.append(tid)
                elif task.get('started_at'):
                    started = datetime.fromisoformat(task['started_at'])
                    if (now - started).total_seconds() > 600:
                        stale.append(tid)
            for tid in stale:
                del tasks[tid]
            if stale:
                logger.info(f'Cleaned up {len(stale)} stale tasks')


cleanup_thread = threading.Thread(target=cleanup_stale_tasks, daemon=True)
cleanup_thread.start()


# ═══════════════════════════════════════════════════════════════════════
# VALIDATION HELPERS
# ═══════════════════════════════════════════════════════════════════════

def validate_input(query_type, target):
    import re
    target = target.strip()
    if not target:
        return False, 'Target cannot be empty'

    if query_type == 'email':
        if not re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', target):
            return False, 'Invalid email format'
        return True, target.lower()

    elif query_type == 'username':
        if len(target) < 2:
            return False, 'Username must be at least 2 characters'
        if not re.match(r'^[a-zA-Z0-9_.\-]+$', target):
            return False, 'Username contains invalid characters'
        return True, target

    elif query_type == 'phone':
        cleaned = target.lstrip('+').replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        if not cleaned.replace('+', '').isdigit():
            return False, 'Phone number must contain only digits, spaces, or +'
        if len(cleaned) < 7 or len(cleaned) > 15:
            return False, 'Phone number length seems invalid'
        if not target.startswith('+'):
            target = '+' + target
        return True, target

    elif query_type == 'domain':
        domain = re.sub(r'^https?://', '', target).split('/')[0]
        if not re.match(r'^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', domain):
            return False, 'Invalid domain format'
        return True, domain.lower()

    elif query_type == 'ip':
        parts = target.split('.')
        if len(parts) != 4:
            return False, 'IP must be in x.x.x.x format'
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False, 'Invalid IP octet values'
        return True, target

    return False, 'Invalid query type'


# ═══════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/config')
def get_config():
    resp = make_response(jsonify(Config.apis_configured()))
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/api/lookup', methods=['POST'])
@rate_limit
def start_lookup():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body must be JSON'}), 400

    query_type = data.get('type', '').lower()
    target = data.get('target', '')

    if query_type not in ['email', 'username', 'phone', 'domain', 'ip']:
        return jsonify({'error': 'Invalid query type. Must be one of: email, username, phone, domain, ip'}), 400

    valid, result = validate_input(query_type, target)
    if not valid:
        return jsonify({'error': result}), 400
    target = result

    raw = f'{query_type}:{target}:{time.time()}:{request.remote_addr}'
    task_id = hashlib.sha256(raw.encode()).hexdigest()[:16]

    thread = threading.Thread(
        target=background_lookup,
        args=(task_id, query_type, target),
        daemon=True,
    )
    thread.start()

    logger.info(f'Started lookup: type={query_type} target={target} task_id={task_id}')
    return jsonify({
        'task_id': task_id,
        'status': 'queued',
        'type': query_type,
        'target': target,
    }), 202


@app.route('/api/status/<task_id>')
def get_status(task_id):
    task = get_task(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify(task)


@app.route('/api/health')
def health():
    active = sum(1 for t in tasks.values() if t.get('status') == 'running')
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.utcnow().isoformat(),
        'active_tasks': active,
        'config_status': Config.apis_configured(),
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    logger.exception('Internal server error')
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=Config.DEBUG)
