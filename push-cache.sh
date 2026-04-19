#!/bin/bash
# Deploy CACHE inventory app to production
set -e

PROD_HOST="159.203.111.124"
PROD_USER="root"

echo "==> Switching to main..."
git checkout main

echo "==> Merging dev into main..."
git merge dev --no-edit

echo "==> Pushing main to GitHub..."
git push origin main

echo "==> Deploying CACHE to production ($PROD_HOST)..."
ssh "$PROD_USER@$PROD_HOST" "cd /var/www/HomeProject && git pull origin main && bash cache/scripts/deploy.sh"

echo "==> Switching back to dev..."
git checkout dev

echo ""
echo "✓ CACHE deploy complete — $PROD_HOST:3001"
