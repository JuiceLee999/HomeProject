#!/bin/bash
# Server-side deploy script — runs on 174.138.90.222
set -e

DEPLOY_DIR="/var/www/HomeProject"

echo "==> Deploying HomeWorks..."
cd "$DEPLOY_DIR"

echo "==> Pulling latest from main..."
git pull origin main

echo "==> Installing dependencies..."
npm install --omit=dev

echo "==> Clearing stale DB lock (if any)..."
rm -rf "$DEPLOY_DIR/db/homeworks.db.lock"

echo "==> Restarting app..."
if command -v pm2 &> /dev/null; then
  # Use ecosystem.config.js if present (holds env vars like APP_URL, SMTP_*)
  if [ -f "$DEPLOY_DIR/ecosystem.config.js" ]; then
    pm2 restart ecosystem.config.js --update-env 2>/dev/null || pm2 start ecosystem.config.js
  else
    pm2 restart homeworks 2>/dev/null || pm2 start server.js --name homeworks
  fi
else
  echo "WARNING: pm2 not found. Install it: npm install -g pm2"
fi

echo "==> Done. HomeWorks is live."
