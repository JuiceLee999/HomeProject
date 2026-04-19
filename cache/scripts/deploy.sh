#!/bin/bash
# Server-side deploy script for CACHE inventory app
set -e

REPO_DIR="/var/www/HomeProject"
APP_DIR="$REPO_DIR/cache"

echo "==> Deploying CACHE..."
cd "$REPO_DIR"

echo "==> Pulling latest from main..."
git pull origin main

echo "==> Installing dependencies..."
cd "$APP_DIR"
npm install --omit=dev

echo "==> Clearing DB lock (if any)..."
rm -rf "$APP_DIR/db/cache.db.lock"

echo "==> Restarting app..."
if command -v pm2 &> /dev/null; then
  pm2 restart cache-inventory 2>/dev/null || pm2 start server.js --name cache-inventory --cwd "$APP_DIR"
else
  echo "WARNING: pm2 not found."
fi

echo "==> Done. CACHE is live on port 3001."
