#!/bin/bash
# One-time PostgreSQL setup for SHIT inventory app
set -e

DB_USER="shit_app"
DB_NAME="inventory"
DB_PASS=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)

echo "==> Installing PostgreSQL..."
apt-get update -q
apt-get install -y postgresql

echo "==> Starting PostgreSQL..."
systemctl enable postgresql
systemctl start postgresql

echo "==> Creating database user and database..."
sudo -u postgres psql <<SQL
CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';
CREATE DATABASE $DB_NAME OWNER $DB_USER;
SQL

DATABASE_URL="postgresql://$DB_USER:$DB_PASS@localhost:5432/$DB_NAME"

echo "==> Saving DATABASE_URL to /root/.bashrc..."
sed -i '/^export DATABASE_URL=/d' /root/.bashrc
echo "export DATABASE_URL=\"$DATABASE_URL\"" >> /root/.bashrc
source /root/.bashrc

echo ""
echo "==> PostgreSQL is ready!"
echo "    DATABASE_URL=$DATABASE_URL"
echo ""
echo "==> Run the data migration next:"
echo "    cd /var/www/HomeProject/cache"
echo "    npm install"
echo "    DATABASE_URL=\"$DATABASE_URL\" node scripts/migrate-sqlite-to-pg.js"
