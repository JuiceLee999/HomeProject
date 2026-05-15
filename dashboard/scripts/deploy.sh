#!/bin/bash
# Server-side deploy script for Dashboard — runs on 159.203.111.124
set -e

REPO_DIR="/var/www/HomeProject"
APP_DIR="$REPO_DIR/dashboard"
NGINX_CONF="/etc/nginx/sites-available/homeworks"

echo "==> Deploying Dashboard..."
cd "$REPO_DIR"

echo "==> Pulling latest from main..."
git pull origin main

echo "==> Installing dependencies..."
cd "$APP_DIR"
npm install --omit=dev

echo "==> Starting/restarting app..."
if command -v pm2 &> /dev/null; then
  BASE_PATH=/dash pm2 restart dashboard 2>/dev/null || \
    BASE_PATH=/dash pm2 start server.js --name dashboard --cwd "$APP_DIR"
  pm2 save
else
  echo "WARNING: pm2 not found. Install it: npm install -g pm2"
fi

echo "==> Checking nginx config for /dash route..."
if grep -q "location /dash" "$NGINX_CONF"; then
  echo "    nginx already has /dash route — skipping."
else
  echo "    Adding /dash route to nginx..."
  # Insert before the closing brace of the server block
  sed -i '/^}/i\
\
    location /dash {\
        proxy_pass http://localhost:3005;\
        proxy_http_version 1.1;\
        proxy_set_header Upgrade $http_upgrade;\
        proxy_set_header Connection '"'"'upgrade'"'"';\
        proxy_set_header Host $host;\
        proxy_set_header X-Real-IP $remote_addr;\
        proxy_set_header X-Forwarded-Proto $scheme;\
        proxy_cache_bypass $http_upgrade;\
    }' "$NGINX_CONF"

  echo "==> Testing nginx config..."
  nginx -t

  echo "==> Reloading nginx..."
  systemctl reload nginx
  echo "    nginx reloaded."
fi

echo ""
echo "==> Done. Dashboard is live on port 3005 at /dash"
echo "    https://honey-do.hopto.org/dash"
