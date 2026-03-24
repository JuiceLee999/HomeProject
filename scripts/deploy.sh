#!/bin/bash
# Server-side deploy script — runs on 174.138.90.222
# Pulls latest main branch into /var/www/HomeProject

set -e

DEPLOY_DIR="/var/www/HomeProject"

echo "==> Deploying HomeWorks..."

cd "$DEPLOY_DIR"

echo "==> Pulling latest from main..."
git pull origin main

echo "==> Done. HomeWorks is up to date."
