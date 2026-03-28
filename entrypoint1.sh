#!/bin/bash
# Inject Railway env vars into the dashboard HTML at container startup
sed \
  -e "s|YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com|${LP_GOOGLE_CLIENT_ID}|g" \
  -e "s|https://buy.stripe.com/YOUR_LINK|${LP_STRIPE_LINK}|g" \
  /tmp/index.template.html > /usr/share/nginx/html/index.html

echo "Config injected: Google=${LP_GOOGLE_CLIENT_ID:0:20}... Stripe=${LP_STRIPE_LINK:0:35}..."
nginx -g "daemon off;"
