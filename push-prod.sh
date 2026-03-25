#!/bin/bash
# Local script — merges dev into main, pushes, then deploys to prod
# Usage: bash push-prod.sh

set -e

PROD_HOST="159.203.111.124"
PROD_USER="root"
PROD_DIR="/var/www/HomeProject"

echo "==> Switching to main..."
git checkout main

echo "==> Merging dev into main..."
git merge dev --no-edit

echo "==> Pushing main to GitHub..."
git push origin main

echo "==> Deploying to production ($PROD_HOST)..."
ssh "$PROD_USER@$PROD_HOST" "bash $PROD_DIR/scripts/deploy.sh"

echo "==> Switching back to dev..."
git checkout dev

echo ""
echo "✓ Production deploy complete — $PROD_HOST"
