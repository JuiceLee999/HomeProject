#!/bin/bash
# Server-side deploy script for SHIT inventory app
set -e

REPO_DIR="/var/www/HomeProject"
APP_DIR="$REPO_DIR/inventory"

echo "==> Deploying SHIT..."
cd "$REPO_DIR"

echo "==> Pulling latest from main..."
git pull origin main

echo "==> Installing dependencies..."
cd "$APP_DIR"
npm install --omit=dev

echo "==> Restarting app..."
if command -v pm2 &> /dev/null; then
  pm2 delete cache-inventory 2>/dev/null || true
  ANTHROPIC_API_KEY=$(grep 'ANTHROPIC_API_KEY' /root/.bashrc | cut -d'"' -f2) \
  JWT_SECRET=$(grep 'JWT_SECRET' /root/.bashrc | cut -d'"' -f2) \
  DATABASE_URL=$(grep 'DATABASE_URL' /root/.bashrc | cut -d'"' -f2) \
  pm2 start server.js --name cache-inventory --cwd "$APP_DIR"
  pm2 save
else
  echo "WARNING: pm2 not found."
fi

echo "==> Done. SHIT is live on port 3001."
