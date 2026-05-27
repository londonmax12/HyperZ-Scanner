FROM drupal:7-apache

# vuln-drupal: a real Drupal 7 install (Apache + PHP + MariaDB
# co-hosted, site-install driven by drush on first boot) so
# drupal-changelog-disclosure exercises the live Drupal HTML
# surface, the fingerprinter's Drupal detection against actual
# Drupal output, and the applies_to dispatch path end-to-end.
#
# MariaDB runs in the same container so the harness stays
# single-image-per-target like every other vuln-* fixture. Production
# Drupal runs the database on a separate host; the check operates at
# the HTTP layer, so the co-hosted DB is observationally identical
# from the scanner's perspective. Same shape as vuln-wordpress.
#
# Drupal 7 hit end-of-life on 2025-01-05. The image is no longer
# receiving updates, but the docker.io/library/drupal:7-apache tag is
# still pullable and pins to the final 7.103 release - which is
# exactly the deployment shape the real-world disclosure check
# targets, since 7.x sites that did not migrate are the ones still
# serving CHANGELOG.txt at docroot in the wild.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      mariadb-server \
      ca-certificates \
      curl \
      less \
 && rm -rf /var/lib/apt/lists/*

# Drush 8's D7 site-install sends a welcome email to the admin
# account via PHP's mail(), which on Linux shells out to
# /usr/sbin/sendmail. The slim apache image ships no MTA, so the
# send fails and drush bubbles a non-zero exit even though the
# install itself completed. Point PHP at /bin/true so mail() silently
# no-ops; the fixture doesn't deliver mail anywhere, so dropping it
# is the correct behaviour.
RUN echo 'sendmail_path = "/bin/true"' \
      > /usr/local/etc/php/conf.d/disable-sendmail.ini

# drush 8.x is the only drush line compatible with Drupal 7. 8.4.12
# is the final release of that line, pinned by exact tag so the build
# is reproducible if a future 8.5.x slips out.
RUN curl -fsSL -o /usr/local/bin/drush \
      https://github.com/drush-ops/drush/releases/download/8.4.12/drush.phar \
 && chmod +x /usr/local/bin/drush

ENV DRUPAL_DB_HOST=127.0.0.1 \
    DRUPAL_DB_USER=drupal \
    DRUPAL_DB_PASSWORD=drupal \
    DRUPAL_DB_NAME=drupal

COPY init.sh /usr/local/bin/vuln-drupal-init.sh
RUN chmod +x /usr/local/bin/vuln-drupal-init.sh

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/vuln-drupal-init.sh"]
CMD ["apache2-foreground"]
