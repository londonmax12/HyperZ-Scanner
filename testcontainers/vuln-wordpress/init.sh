#!/usr/bin/env bash
# Boot MariaDB, hand off to the upstream WordPress entrypoint to write
# wp-config.php + start Apache, then run `wp core install` so
# /wp-json/wp/v2/users returns real user records. The harness waits on
# the "vuln-wordpress ready" log line below before starting the scan,
# so install always completes before any probe lands.
set -euo pipefail

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

mysql -uroot <<'SQL'
CREATE DATABASE IF NOT EXISTS wordpress;
CREATE USER IF NOT EXISTS 'wordpress'@'localhost' IDENTIFIED BY 'wordpress';
GRANT ALL ON wordpress.* TO 'wordpress'@'localhost';
FLUSH PRIVILEGES;
SQL

# Tell WordPress to derive WP_HOME / WP_SITEURL from the live Host
# header instead of the value baked in at install time. Required
# because the testcontainers harness maps the container's :80 to a
# random host port; without dynamic siteurl, every response 301s to
# http://localhost/ (the install --url) and the scanner's fingerprint
# probe follows the redirect to a dead port and errors the scan out.
# The HTTP_HOST guard skips the override during wp-cli runs (no
# request context) so the install args remain authoritative there.
# WORDPRESS_CONFIG_EXTRA is the official entrypoint's hook for
# inlining extra PHP into wp-config.php at generation time.
export WORDPRESS_CONFIG_EXTRA='if (!empty($_SERVER["HTTP_HOST"])) { define("WP_HOME", "http://" . $_SERVER["HTTP_HOST"]); define("WP_SITEURL", "http://" . $_SERVER["HTTP_HOST"]); }'

# The WordPress entrypoint copies /usr/src/wordpress -> /var/www/html
# and materializes wp-config.php from the WORDPRESS_DB_* env vars,
# then execs the CMD. Run it in the background so we can drive wp-cli
# against Apache before declaring the container ready.
docker-entrypoint.sh "$@" &
APACHE_PID=$!

for _ in $(seq 1 60); do
  if curl -sSf -o /dev/null http://127.0.0.1/wp-login.php; then break; fi
  sleep 1
done

cd /var/www/html

if ! wp --allow-root core is-installed 2>/dev/null; then
  wp --allow-root core install \
    --url=http://localhost \
    --title="vuln-wordpress" \
    --admin_user=admin \
    --admin_password=admin-password \
    --admin_email=admin@example.invalid \
    --skip-email

  # /wp-json/wp/v2/users only lists users with a published post, so
  # seed an admin post + a secondary author with their own post. The
  # check's finding evidence then names multiple disclosed slugs,
  # matching what an operator would see against a real WP site.
  wp --allow-root user create author1 author1@example.invalid \
    --role=author --user_pass=author1-password
  wp --allow-root post create \
    --post_author=admin --post_status=publish --post_title="Hello"
  wp --allow-root post create \
    --post_author=author1 --post_status=publish --post_title="First post"
fi

echo "[vuln-wordpress] ready; serving WordPress on :80"

wait "$APACHE_PID"
