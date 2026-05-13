#!/bin/bash
# Server-side deploy script for SteelLog
set -e

REPO_DIR="/var/www/HomeProject"
APP_DIR="$REPO_DIR/SteelLog"

echo "==> Deploying SteelLog..."
cd "$REPO_DIR"

echo "==> Pulling latest from main..."
git pull origin main

echo "==> Installing dependencies..."
cd "$APP_DIR"
npm install --omit=dev

echo "==> Restarting app..."
if command -v pm2 &> /dev/null; then
  pm2 delete steellog 2>/dev/null || true
  BASE_PATH=/sl \
  PORT=3003 \
  JWT_SECRET=$(grep 'JWT_SECRET' /root/.bashrc | cut -d'"' -f2) \
  SL_DATABASE_URL=$(grep 'SL_DATABASE_URL' /root/.bashrc | cut -d'"' -f2) \
  pm2 start server.js --name steellog --cwd "$APP_DIR"
  pm2 save
else
  echo "WARNING: pm2 not found."
fi

echo "==> Done. SteelLog is live on port 3003 at /sl"
