#!/bin/sh
# Puts the test routes into the framework skeletons created in the Dockerfile.
set -e
SRC=/e2e-apps

# plain PHP: no Composer, started by auto_prepend_file (nginx.conf)
mkdir -p /apps/plain/public
cp $SRC/plain/public/*.php /apps/plain/public/
printf 'auto_prepend_file = /sdk/prepend.php\n' > /apps/plain/public/.user.ini

# Slim
mkdir -p /apps/slim/public
cp $SRC/slim/public/index.php /apps/slim/public/index.php

# Laravel
cp $SRC/laravel/routes/web.php /apps/laravel/routes/web.php
cd /apps/laravel
[ -f .env ] || cp .env.example .env
php artisan key:generate --force >/dev/null 2>&1 || true
sed -i 's/^APP_DEBUG=.*/APP_DEBUG=false/; s/^LOG_CHANNEL=.*/LOG_CHANNEL=single/; s/^SESSION_DRIVER=.*/SESSION_DRIVER=file/; s/^CACHE_STORE=.*/CACHE_STORE=file/' .env
touch database/database.sqlite
php artisan migrate --force >/dev/null 2>&1 || true

# Symfony
mkdir -p /apps/symfony/src/Controller
cp $SRC/symfony/src/Controller/E2eController.php /apps/symfony/src/Controller/E2eController.php
php -r '
$file = "/apps/symfony/config/bundles.php";
$code = file_get_contents($file);
if (strpos($code, "SecureNowBundle") === false) {
    $code = preg_replace("/\\];\\s*$/", "    SecureNow\\\\Integrations\\\\Symfony\\\\SecureNowBundle::class => [\"all\" => true],\n];\n", $code);
    file_put_contents($file, $code);
}'
sed -i 's/^APP_ENV=.*/APP_ENV=prod/' /apps/symfony/.env
cd /apps/symfony && php bin/console cache:clear --env=prod >/dev/null 2>&1 || true

chown -R www-data:www-data /apps/laravel/storage /apps/laravel/bootstrap/cache /apps/laravel/database /apps/symfony/var
