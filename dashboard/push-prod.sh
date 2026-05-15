#!/bin/bash
# Local script — merges dev into main, pushes, then deploys dashboard to prod
set -e

PROD_HOST="159.203.111.124"
PROD_USER="root"
PROD_DIR="/var/www/HomeProject"

# Run git commands from repo root
cd "$(dirname "$0")/.."

echo "==> Switching to main..."
git checkout main

echo "==> Merging dev into main..."
git merge dev --no-edit

echo "==> Pushing main to GitHub..."
git push origin main

echo "==> Deploying to production ($PROD_HOST)..."
ssh "$PROD_USER@$PROD_HOST" "cd $PROD_DIR && git pull origin main && bash $PROD_DIR/dashboard/scripts/deploy.sh"

echo "==> Switching back to dev..."
git checkout dev

echo ""
echo "✓ Production deploy complete — https://honey-do.hopto.org/dash"
