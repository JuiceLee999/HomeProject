#!/bin/bash
# Server-side deploy script — runs on 174.138.90.222
set -e

DEPLOY_DIR="/var/www/HomeProject"

echo "==> Deploying Honey-Do..."
cd "$DEPLOY_DIR"

echo "==> Pulling latest from main..."
git pull origin main

echo "==> Installing dependencies..."
npm install --omit=dev

echo "==> Clearing stale DB lock (if any)..."
rm -rf "$DEPLOY_DIR/db/homeworks.db.lock"

echo "==> Restarting app..."
if command -v pm2 &> /dev/null; then
  pm2 restart homeworks 2>/dev/null || pm2 start server.js --name homeworks
else
  echo "WARNING: pm2 not found. Install it: npm install -g pm2"
fi

echo "==> Done. Honey-Do is live."
