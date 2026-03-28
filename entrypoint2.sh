#!/bin/bash
sed \
  -e "s|YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com|${LP_GOOGLE_CLIENT_ID}|g" \
  -e "s|https://buy.stripe.com/YOUR_LINK|${LP_STRIPE_LINK}|g" \
  -e "s|window.LP_API_BASE || ''|'${LP_API_BASE}'|g" \
  /tmp/index.template.html > /usr/share/nginx/html/index.html

echo "Injected: Google=${LP_GOOGLE_CLIENT_ID:0:20}... Stripe=${LP_STRIPE_LINK:0:35}... API=${LP_API_BASE}"
nginx -g "daemon off;"
