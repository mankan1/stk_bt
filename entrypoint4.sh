#!/bin/bash
set -e

# Railway injects $PORT dynamically — default to 8080 if not set
export PORT="${PORT:-8080}"

echo "Starting on PORT=${PORT}"

# 1. Inject env vars into index.html
sed \
  -e "s|YOUR_GOOGLE_CLIENT_ID\.apps\.googleusercontent\.com|${LP_GOOGLE_CLIENT_ID}|g" \
  -e "s|https://buy\.stripe\.com/YOUR_LINK|${LP_STRIPE_LINK}|g" \
  -e "s|window\.LP_API_BASE || ''|'${LP_API_BASE}'|g" \
  /tmp/index.template.html > /usr/share/nginx/html/index.html

echo "Injected: Google=${LP_GOOGLE_CLIENT_ID:0:20}... Stripe=${LP_STRIPE_LINK:0:35}... API=${LP_API_BASE}"

# 2. Substitute $PORT (and $LP_API_BASE) into nginx config
envsubst '${PORT} ${LP_API_BASE}' \
  < /etc/nginx/templates/default.conf.template \
  > /etc/nginx/conf.d/default.conf

# 3. Remove the default nginx config so ours takes over
rm -f /etc/nginx/conf.d/default.conf.bak
nginx -t && echo "nginx config OK"

# 4. Start nginx
exec nginx -g "daemon off;"
