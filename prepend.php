<?php

declare(strict_types=1);

/*
 * SecureNow without touching the app, or without Composer:
 *
 *   php.ini / .user.ini      auto_prepend_file = /path/to/vendor/securenow/securenow/prepend.php
 *   PHP-FPM pool             php_admin_value[auto_prepend_file] = /path/to/.../prepend.php
 *   Apache .htaccess         php_value auto_prepend_file /path/to/.../prepend.php
 *   or, first line of index.php / wp-config.php:
 *                            require '/path/to/securenow/prepend.php';
 *
 * It registers an autoloader for the SecureNow classes only, then starts the SDK. When the app
 * later loads Composer's autoloader, nothing starts twice.
 */

if (!defined('SECURENOW_PREPENDED')) {
    define('SECURENOW_PREPENDED', true);

    spl_autoload_register(static function (string $class): void {
        if (strncmp($class, 'SecureNow\\', 10) !== 0) {
            return;
        }
        $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, 10)) . '.php';
        if (is_file($file)) {
            require $file;
        }
    });

    require __DIR__ . '/src/bootstrap.php';
}
