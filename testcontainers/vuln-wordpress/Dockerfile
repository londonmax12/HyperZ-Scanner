FROM wordpress:6.4-apache

# vuln-wordpress: a real WordPress install (not a mocked endpoint) so
# the wp-rest-user-enum integration test exercises the live
# /wp-json/wp/v2/users surface, the fingerprinter's WP detection
# against actual WP HTML, and the applies_to dispatch path end-to-end.
#
# MariaDB runs in the same container so the harness stays
# single-image-per-target like every other vuln-* fixture. Production
# WordPress runs MariaDB on a separate host; the check operates at the
# HTTP layer, so the co-hosted DB is observationally identical from
# the scanner's perspective.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      mariadb-server \
      ca-certificates \
      curl \
      less \
 && rm -rf /var/lib/apt/lists/*

# WP-CLI drives the wp core install + seed-user steps on first boot.
RUN curl -fsSL -o /usr/local/bin/wp \
      https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
 && chmod +x /usr/local/bin/wp

ENV WORDPRESS_DB_HOST=127.0.0.1 \
    WORDPRESS_DB_USER=wordpress \
    WORDPRESS_DB_PASSWORD=wordpress \
    WORDPRESS_DB_NAME=wordpress

COPY init.sh /usr/local/bin/vuln-wp-init.sh
RUN chmod +x /usr/local/bin/vuln-wp-init.sh

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/vuln-wp-init.sh"]
CMD ["apache2-foreground"]
