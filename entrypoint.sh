#!/bin/sh
set -e

export PORT="${PORT:-8080}"
echo "Starting on PORT=${PORT}"

# Use Python for injection — avoids all sed escaping issues with URLs and special chars
python3 - <<'PYEOF'
import os

src = open('/tmp/index.template.html', 'r').read()

google = os.environ.get('LP_GOOGLE_CLIENT_ID', '')
stripe = os.environ.get('LP_STRIPE_LINK', '')
api    = os.environ.get('LP_API_BASE', '')

src = src.replace(
    "window.LP_GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com'",
    f"'{google}'"
)
src = src.replace(
    "window.LP_STRIPE_LINK       || 'https://buy.stripe.com/YOUR_LINK'",
    f"'{stripe}'"
)
src = src.replace(
    "window.LP_API_BASE || ''",
    f"'{api}'"
)

open('/usr/share/nginx/html/index.html', 'w').write(src)
print(f"Injected: Google={google[:20]}... Stripe={stripe[:35]}... API={api}")
PYEOF

# Substitute $PORT into nginx config
envsubst '${PORT}' \
  < /etc/nginx/templates/default.conf.template \
  > /etc/nginx/conf.d/default.conf

nginx -t && echo "nginx config OK"
exec nginx -g "daemon off;"
