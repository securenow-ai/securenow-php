# End-to-end image: nginx + PHP-FPM serving four real apps (plain PHP, Slim, Laravel, Symfony)
# with the SecureNow SDK installed from the working copy.
#
#   docker build -f tests/e2e/Dockerfile --build-arg PHP_VERSION=8.3 --build-arg WITH_OTEL=0 -t securenow-php-e2e .
ARG PHP_VERSION=8.3
FROM php:${PHP_VERSION}-fpm-alpine

ARG WITH_OTEL=0
ARG WITH_APCU=0

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY --from=mlocati/php-extension-installer /usr/bin/install-php-extensions /usr/local/bin/

RUN apk add --no-cache nginx curl git unzip sqlite \
 && install-php-extensions pdo_sqlite zip intl opcache pcntl \
 && if [ "$WITH_OTEL" = "1" ]; then install-php-extensions opentelemetry; fi \
 && if [ "$WITH_APCU" = "1" ]; then install-php-extensions apcu; fi

ENV COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_NO_INTERACTION=1 COMPOSER_MEMORY_LIMIT=-1

# Framework skeletons first: these layers survive SDK changes.
RUN mkdir -p /apps \
 && composer create-project --prefer-dist --no-progress laravel/laravel /apps/laravel \
 && composer create-project --prefer-dist --no-progress symfony/skeleton /apps/symfony \
 && cd /apps/symfony && composer require --no-progress symfony/monolog-bundle \
 && mkdir -p /apps/slim && cd /apps/slim && composer init --name=e2e/slim --no-interaction \
 && composer require --no-progress slim/slim slim/psr7

RUN if [ "$WITH_OTEL" = "1" ]; then \
      for app in laravel symfony slim; do \
        cd /apps/$app && composer config allow-plugins.php-http/discovery false \
        && composer config allow-plugins.tbachert/spi true \
        && composer require --no-progress --with-all-dependencies open-telemetry/sdk nyholm/psr7 open-telemetry/opentelemetry-auto-pdo || exit 1; \
      done; \
      cd /apps/laravel && composer require --no-progress open-telemetry/opentelemetry-auto-laravel; \
      cd /apps/symfony && composer require --no-progress open-telemetry/opentelemetry-auto-symfony; \
      cd /apps/slim && composer require --no-progress open-telemetry/opentelemetry-auto-slim; \
    fi

# The SDK, as a Composer path repository (symlinked, so a bind mount of the working copy on /sdk
# is picked up without a rebuild).
COPY . /sdk
RUN for app in laravel symfony slim; do \
      cd /apps/$app \
      && composer config repositories.securenow '{"type":"path","url":"/sdk","options":{"symlink":true}}' \
      && composer require --no-progress 'securenow/securenow:@dev' || exit 1; \
    done

COPY tests/e2e/apps/ /e2e-apps/
COPY tests/e2e/nginx.conf /etc/nginx/http.d/default.conf
COPY tests/e2e/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && sh /e2e-apps/install.sh

EXPOSE 8081 8082 8083 8084
ENTRYPOINT ["/entrypoint.sh"]
