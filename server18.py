"""
Livermore Protocol — Auth + Payment Backend
Runs alongside the static dashboard on Railway.

Endpoints:
  POST /api/verify-google        → verify Google JWT, return session token
  GET  /api/check-pro            → check if user is PRO subscriber
  POST /api/stripe-webhook       → receive Stripe events, update DB
  GET  /api/admin/subscribers    → list all subscribers (admin only)
  GET  /api/admin/grant-pro      → manually grant PRO (admin only)
  GET  /api/admin/revoke-pro     → manually revoke PRO (admin only)
  GET  /health                   → health check
"""

import os, json, time, hmac, hashlib, sqlite3, urllib.request, urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ── Config from Railway env vars ──────────────────────────────────────────────
GOOGLE_CLIENT_ID      = os.environ.get('LP_GOOGLE_CLIENT_ID', '')
STRIPE_WEBHOOK_SECRET = os.environ.get('LP_STRIPE_WEBHOOK_SECRET', '')  # whsec_...
ADMIN_SECRET          = os.environ.get('LP_ADMIN_SECRET', '')
PORT                  = int(os.environ.get('PORT', 8080))
DB_PATH               = os.environ.get('DB_PATH', '/data/subscribers.db')

# ── SQLite DB ─────────────────────────────────────────────────────────────────
def init_db():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS subscribers (
            email                  TEXT PRIMARY KEY,
            google_sub             TEXT,
            stripe_customer_id     TEXT,
            stripe_subscription_id TEXT,
            is_pro                 INTEGER DEFAULT 0,
            created_at             REAL,
            updated_at             REAL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            email      TEXT,
            google_sub TEXT,
            name       TEXT,
            picture    TEXT,
            created_at REAL,
            expires_at REAL
        )
    ''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ── Google JWT verification ───────────────────────────────────────────────────
def verify_google_jwt(credential):
    try:
        url = f'https://oauth2.googleapis.com/tokeninfo?id_token={credential}'
        with urllib.request.urlopen(url, timeout=5) as r:
            payload = json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise ValueError(f'Google tokeninfo failed: {e.code}')

    if GOOGLE_CLIENT_ID and payload.get('aud') != GOOGLE_CLIENT_ID:
        raise ValueError('Token audience mismatch')

    if int(payload.get('exp', 0)) < time.time():
        raise ValueError('Token expired')

    return payload

def make_session_token(email, sub):
    raw = f'{email}:{sub}:{time.time()}:{os.urandom(16).hex()}'
    return hashlib.sha256(raw.encode()).hexdigest()

# ── Stripe webhook verification ───────────────────────────────────────────────
def verify_stripe_signature(payload_bytes, sig_header):
    if not STRIPE_WEBHOOK_SECRET:
        return True  # Skip in dev if not configured
    try:
        parts   = dict(x.split('=', 1) for x in sig_header.split(','))
        timestamp = parts.get('t', '')
        v1_sig    = parts.get('v1', '')
        signed_payload = f'{timestamp}.'.encode() + payload_bytes

        # Fix: strip 'whsec_' prefix correctly — slice not lstrip
        secret = STRIPE_WEBHOOK_SECRET
        if secret.startswith('whsec_'):
            secret = secret[6:]

        expected = hmac.new(
            secret.encode(),
            signed_payload,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected, v1_sig):
            return False
        if abs(time.time() - int(timestamp)) > 300:
            return False
        return True
    except Exception as e:
        print(f'[webhook] Signature error: {e}')
        return False

# ── Admin auth helper ─────────────────────────────────────────────────────────
def is_admin(headers):
    if not ADMIN_SECRET:
        return False
    auth = headers.get('Authorization', '').replace('Bearer ', '').strip()
    return auth == ADMIN_SECRET

# ── HTTP Handler ──────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f'[{self.address_string()}] {fmt % args}')

    def send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        length = self.headers.get('Content-Length')
        if length:
            return self.rfile.read(int(length))
        te = self.headers.get('Transfer-Encoding', '')
        if 'chunked' in te.lower():
            body = b''
            while True:
                line = self.rfile.readline().strip()
                try:
                    chunk_len = int(line, 16)
                except ValueError:
                    break
                if chunk_len == 0:
                    break
                body += self.rfile.read(chunk_len)
                self.rfile.readline()
            return body
        return b''

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        qs     = parse_qs(parsed.query)

        # ── GET /health ───────────────────────────────────────────────────────
        if path == '/health':
            self.send_json(200, {'status': 'ok', 'time': time.time()})

        # ── GET /api/check-pro ────────────────────────────────────────────────
        elif path == '/api/check-pro':
            token = self.headers.get('Authorization', '').replace('Bearer ', '').strip()
            email = qs.get('email', [None])[0]
            db = get_db()
            try:
                # Try session token first
                if token:
                    row = db.execute(
                        'SELECT s.email, s.name, s.picture, sub.is_pro '
                        'FROM sessions s LEFT JOIN subscribers sub ON s.email=sub.email '
                        'WHERE s.token=? AND s.expires_at>?',
                        (token, time.time())
                    ).fetchone()
                    if row:
                        self.send_json(200, {
                            'email':  row['email'],
                            'name':   row['name'],
                            'is_pro': bool(row['is_pro']),
                        })
                        return

                # Fall back to email lookup (works even if session expired)
                if email:
                    row = db.execute(
                        'SELECT email, is_pro FROM subscribers WHERE email=?', (email,)
                    ).fetchone()
                    if row:
                        self.send_json(200, {'email': row['email'], 'is_pro': bool(row['is_pro'])})
                        return

                self.send_json(200, {'is_pro': False})
            finally:
                db.close()

        # ── GET /api/admin/subscribers ────────────────────────────────────────
        elif path == '/api/admin/subscribers':
            if not is_admin(self.headers):
                self.send_json(401, {'error': 'Unauthorized'})
                return
            db = get_db()
            try:
                rows = db.execute(
                    'SELECT s.email, s.is_pro, s.stripe_customer_id, s.stripe_subscription_id, '
                    's.created_at, s.updated_at, '
                    'COUNT(sess.token) as session_count, MAX(sess.created_at) as last_login '
                    'FROM subscribers s '
                    'LEFT JOIN sessions sess ON s.email = sess.email '
                    'GROUP BY s.email ORDER BY s.updated_at DESC'
                ).fetchall()
                self.send_json(200, {
                    'total':      len(rows),
                    'pro_count':  sum(1 for r in rows if r['is_pro']),
                    'subscribers': [{
                        'email':           r['email'],
                        'is_pro':          bool(r['is_pro']),
                        'stripe_customer': r['stripe_customer_id'],
                        'stripe_sub':      r['stripe_subscription_id'],
                        'joined':          r['created_at'],
                        'updated':         r['updated_at'],
                        'last_login':      r['last_login'],
                        'sessions':        r['session_count'],
                    } for r in rows]
                })
            finally:
                db.close()

        # ── GET /api/admin/grant-pro ──────────────────────────────────────────
        elif path == '/api/admin/grant-pro':
            if not is_admin(self.headers):
                self.send_json(401, {'error': 'Unauthorized'})
                return
            email = qs.get('email', [None])[0]
            if not email:
                self.send_json(400, {'error': 'Missing ?email='})
                return
            db = get_db()
            try:
                now = time.time()
                db.execute(
                    'INSERT INTO subscribers (email, is_pro, created_at, updated_at) VALUES (?,1,?,?) '
                    'ON CONFLICT(email) DO UPDATE SET is_pro=1, updated_at=excluded.updated_at',
                    (email, now, now)
                )
                db.commit()
                print(f'[admin] Granted PRO: {email}')
                self.send_json(200, {'ok': True, 'email': email, 'is_pro': True})
            finally:
                db.close()

        # ── GET /api/admin/revoke-pro ─────────────────────────────────────────
        elif path == '/api/admin/revoke-pro':
            if not is_admin(self.headers):
                self.send_json(401, {'error': 'Unauthorized'})
                return
            email = qs.get('email', [None])[0]
            if not email:
                self.send_json(400, {'error': 'Missing ?email='})
                return
            db = get_db()
            try:
                db.execute(
                    'UPDATE subscribers SET is_pro=0, updated_at=? WHERE email=?',
                    (time.time(), email)
                )
                db.commit()
                print(f'[admin] Revoked PRO: {email}')
                self.send_json(200, {'ok': True, 'email': email, 'is_pro': False})
            finally:
                db.close()

        else:
            self.send_json(404, {'error': 'Not found'})

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.read_body()

        # ── POST /api/verify-google ───────────────────────────────────────────
        if path == '/api/verify-google':
            try:
                data       = json.loads(body)
                credential = data.get('credential', '')
                if not credential:
                    self.send_json(400, {'error': 'Missing credential'})
                    return

                payload = verify_google_jwt(credential)
                email   = payload.get('email', '')
                sub     = payload.get('sub', '')
                name    = payload.get('name', '')
                picture = payload.get('picture', '')

                if not email or not sub:
                    self.send_json(400, {'error': 'Invalid token payload'})
                    return

                db  = get_db()
                now = time.time()
                try:
                    db.execute('''
                        INSERT INTO subscribers (email, google_sub, is_pro, created_at, updated_at)
                        VALUES (?, ?, 0, ?, ?)
                        ON CONFLICT(email) DO UPDATE SET
                            google_sub=excluded.google_sub,
                            updated_at=excluded.updated_at
                    ''', (email, sub, now, now))

                    token = make_session_token(email, sub)
                    db.execute('''
                        INSERT INTO sessions (token, email, google_sub, name, picture, created_at, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (token, email, sub, name, picture, now, now + 86400))
                    db.commit()

                    row    = db.execute('SELECT is_pro FROM subscribers WHERE email=?', (email,)).fetchone()
                    is_pro = bool(row['is_pro']) if row else False

                    self.send_json(200, {
                        'token':   token,
                        'email':   email,
                        'name':    name,
                        'picture': picture,
                        'is_pro':  is_pro,
                    })
                finally:
                    db.close()

            except ValueError as e:
                self.send_json(401, {'error': str(e)})
            except Exception as e:
                print(f'[verify-google] Error: {e}')
                self.send_json(500, {'error': 'Server error'})

        # ── POST /api/stripe-webhook ──────────────────────────────────────────
        elif path == '/api/stripe-webhook':
            sig = self.headers.get('Stripe-Signature', '')
            te = self.headers.get('Transfer-Encoding', 'none')
            cl = self.headers.get('Content-Length', 'none')
            print(f'[webhook] Received event, body={len(body)}b TE={te} CL={cl}')

            if not verify_stripe_signature(body, sig):
                print('[webhook] Invalid Stripe signature — check LP_STRIPE_WEBHOOK_SECRET')
                self.send_json(400, {'error': 'Invalid signature'})
                return

            try:
                event = json.loads(body)
                etype = event.get('type', '')
                obj   = event.get('data', {}).get('object', {})
                print(f'[webhook] Event: {etype}')

                db  = get_db()
                now = time.time()
                try:
                    if etype == 'checkout.session.completed':
                        email   = obj.get('customer_details', {}).get('email') or obj.get('customer_email', '')
                        cust_id = obj.get('customer', '')
                        sub_id  = obj.get('subscription', '')
                        if email:
                            db.execute('''
                                INSERT INTO subscribers (email, stripe_customer_id, stripe_subscription_id, is_pro, created_at, updated_at)
                                VALUES (?, ?, ?, 1, ?, ?)
                                ON CONFLICT(email) DO UPDATE SET
                                    stripe_customer_id=excluded.stripe_customer_id,
                                    stripe_subscription_id=excluded.stripe_subscription_id,
                                    is_pro=1, updated_at=excluded.updated_at
                            ''', (email, cust_id, sub_id, now, now))
                            db.commit()
                            print(f'[webhook] PRO activated: {email}')

                    elif etype in ('customer.subscription.deleted', 'customer.subscription.paused'):
                        cust_id = obj.get('customer', '')
                        if cust_id:
                            db.execute(
                                'UPDATE subscribers SET is_pro=0, updated_at=? WHERE stripe_customer_id=?',
                                (now, cust_id)
                            )
                            db.commit()
                            print(f'[webhook] PRO revoked: customer {cust_id}')

                    elif etype == 'invoice.payment_failed':
                        cust_id = obj.get('customer', '')
                        print(f'[webhook] Payment failed: customer {cust_id}')

                finally:
                    db.close()

                self.send_json(200, {'received': True})

            except Exception as e:
                print(f'[webhook] Error: {e}')
                self.send_json(200, {'received': True})  # Always 200 to Stripe

        else:
            self.send_json(404, {'error': 'Not found'})


if __name__ == '__main__':
    init_db()
    print(f'[LP Backend] Starting on port {PORT}')
    print(f'[LP Backend] DB: {DB_PATH}')
    print(f'[LP Backend] Google Client ID: {GOOGLE_CLIENT_ID[:20]}...' if GOOGLE_CLIENT_ID else '[LP Backend] Google Client ID: NOT SET')
    print(f'[LP Backend] Stripe Webhook Secret: {"SET" if STRIPE_WEBHOOK_SECRET else "NOT SET"}')
    print(f'[LP Backend] Admin Secret: {"SET" if ADMIN_SECRET else "NOT SET — admin endpoints disabled"}')
    server = HTTPServer(('0.0.0.0', PORT), Handler)
    server.serve_forever()
