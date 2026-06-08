#!/bin/bash
# Server-side deploy script for Himpcamp
set -e

REPO_DIR="/var/www/HomeProject"
APP_DIR="$REPO_DIR/camp"

echo "==> Deploying Himpcamp..."
cd "$REPO_DIR"

echo "==> Pulling latest from main..."
git pull origin main

echo "==> Installing dependencies..."
cd "$APP_DIR"
npm install --omit=dev

echo "==> Restarting app..."
if command -v pm2 &> /dev/null; then
  pm2 delete himpcamp 2>/dev/null || true
  BASE_PATH=/camp \
  PORT=3006 \
  DATABASE_URL=$(grep 'DATABASE_URL' /root/.bashrc | cut -d'"' -f2) \
  JWT_SECRET=$(grep 'JWT_SECRET' /root/.bashrc | cut -d'"' -f2) \
  STRIPE_SECRET_KEY=$(grep 'STRIPE_SECRET_KEY' /root/.bashrc | cut -d'"' -f2) \
  STRIPE_WEBHOOK_SECRET=$(grep 'STRIPE_WEBHOOK_SECRET' /root/.bashrc | cut -d'"' -f2) \
  STRIPE_PUBLISHABLE_KEY=$(grep 'STRIPE_PUBLISHABLE_KEY' /root/.bashrc | cut -d'"' -f2) \
  EMAIL_HOST=$(grep 'EMAIL_HOST' /root/.bashrc | cut -d'"' -f2) \
  EMAIL_PORT=$(grep 'EMAIL_PORT' /root/.bashrc | cut -d'"' -f2) \
  EMAIL_USER=$(grep 'EMAIL_USER' /root/.bashrc | cut -d'"' -f2) \
  EMAIL_PASS=$(grep 'EMAIL_PASS' /root/.bashrc | cut -d'"' -f2) \
  EMAIL_FROM=$(grep 'EMAIL_FROM' /root/.bashrc | cut -d'"' -f2) \
  pm2 start server.js --name himpcamp --cwd "$APP_DIR"
  pm2 save
else
  echo "WARNING: pm2 not found."
fi

echo "==> Done. Himpcamp is live on port 3006 at /camp"
