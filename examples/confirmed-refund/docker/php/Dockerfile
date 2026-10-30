# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# INTENTIONALLY VULNERABLE DEMO IMAGE (contains a remote-code-execution endpoint). Local use only.
# Build context: REPOSITORY ROOT. Same PHP runtime as Demo 2 (examples/confirmed-transfer).
FROM php:8.4-fpm-alpine@sha256:a49524d3cec4a77d1807d0878e5bb38146116ae5489ec60c367aee53bb9b0699
# pdo_pgsql and sockets are installed on purpose: they give attacker code MORE tools, which makes
# the containment probes stronger, not weaker (same reasoning as Demo 1 and Demo 2).
RUN apk add --no-cache libpq \
 && apk add --no-cache --virtual .build-deps $PHPIZE_DEPS postgresql-dev linux-headers \
 && docker-php-ext-install -j"$(nproc)" pdo_pgsql sockets \
 && apk del .build-deps \
 && rm -rf /usr/src/php* /tmp/* \
 && rm -f /usr/local/etc/php-fpm.d/*.conf \
 && addgroup -g 10001 app && adduser -D -H -u 10001 -G app -s /sbin/nologin app \
 && mkdir -p /run/fcgi /run/nodkey && chown 10001:10001 /run/fcgi
COPY examples/php-ledger/docker/php/php-fpm-pool.conf /usr/local/etc/php-fpm.d/www.conf
COPY examples/php-ledger/docker/php/php.ini /usr/local/etc/php/conf.d/zz-nodkey-demo.ini
COPY examples/confirmed-refund/app/ /var/www/app/
RUN chown -R root:root /var/www/app && chmod -R a+rX,go-w /var/www/app
WORKDIR /var/www/app
USER 10001:10001
CMD ["sh", "-c", "chmod -R u+rwX /run/fcgi 2>/dev/null; find /run/fcgi -mindepth 1 -delete; exec php-fpm --nodaemonize"]
