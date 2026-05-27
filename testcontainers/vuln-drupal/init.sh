#!/usr/bin/env bash
# Boot MariaDB, run drush site-install to materialize settings.php +
# install the standard Drupal 7 profile, then exec Apache in the
# foreground. The harness waits on the "vuln-drupal ready" log line
# before starting the scan, so install always completes before any
# probe lands.
set -euo pipefail

# drush 8 looks for config under $HOME; root has no HOME set by
# default in the apache image.
export HOME=/root

mkdir -p /run/mysqld /var/lib/mysql
chown -R mysql:mysql /run/mysqld /var/lib/mysql

if [ ! -d /var/lib/mysql/mysql ]; then
  mariadb-install-db --user=mysql --datadir=/var/lib/mysql >/dev/null
fi

mysqld --user=mysql --datadir=/var/lib/mysql --bind-address=127.0.0.1 &

for _ in $(seq 1 30); do
  if mysqladmin ping --silent 2>/dev/null; then break; fi
  sleep 1
done

mysql -uroot <<SQL
CREATE DATABASE IF NOT EXISTS ${DRUPAL_DB_NAME};
CREATE USER IF NOT EXISTS '${DRUPAL_DB_USER}'@'localhost' IDENTIFIED BY '${DRUPAL_DB_PASSWORD}';
GRANT ALL ON ${DRUPAL_DB_NAME}.* TO '${DRUPAL_DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

cd /var/www/html

# drush site-install writes settings.php into sites/default; that
# directory is www-data-owned out of the image. Loosening it to 777
# for the install is the documented Drupal 7 install flow and would
# normally be re-locked post-install. For an integration fixture we
# leave it open - no operator hardening to mimic here.
chmod 777 sites/default

# Install the standard profile if Drupal isn't already set up. The
# settings.php-with-databases check is the same idempotency guard
# drush itself uses to decide whether install has run.
if [ ! -f sites/default/settings.php ] \
    || ! grep -q "databases" sites/default/settings.php 2>/dev/null; then
  drush --yes --root=/var/www/html site-install standard \
    --db-url="mysql://${DRUPAL_DB_USER}:${DRUPAL_DB_PASSWORD}@${DRUPAL_DB_HOST}/${DRUPAL_DB_NAME}" \
    --site-name="vuln-drupal" \
    --account-name=admin \
    --account-pass=admin-password
fi

# settings.php is created mode 444 by drush. Leaving it strict is the
# correct production posture and Drupal serves traffic fine that way.

echo "[vuln-drupal] ready; serving Drupal on :80"

exec docker-php-entrypoint "$@"
