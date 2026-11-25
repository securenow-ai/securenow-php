<?php

/**
 * Plugin Name: SecureNow
 * Description: SecureNow for WordPress: request traces, logs, and the in-app firewall (IP blocking, rate limits, challenges, scraper blocking).
 * Version: 1.0.0
 * Author: SecureNow
 * Author URI: https://securenow.ai
 * License: ISC
 *
 * Install as a must-use plugin: copy this file to wp-content/mu-plugins/securenow.php.
 *
 * For the firewall to answer before WordPress loads at all, also add this as the first line of
 * wp-config.php (or set it as auto_prepend_file):
 *
 *   require __DIR__ . '/vendor/securenow/securenow/prepend.php';
 *
 * Credentials: .securenow/runtime.php next to wp-config.php (a .php file is never served as
 * text), or SECURENOW_CREDENTIALS_FILE pointing outside the web root.
 */

if (!defined('ABSPATH')) {
    exit;
}

(static function (): void {
    if (!class_exists(\SecureNow\SecureNow::class)) {
        $candidates = [
            ABSPATH . 'vendor/securenow/securenow/prepend.php',
            dirname(ABSPATH) . '/vendor/securenow/securenow/prepend.php',
            WP_CONTENT_DIR . '/vendor/securenow/securenow/prepend.php',
            WP_CONTENT_DIR . '/securenow/prepend.php',
        ];
        foreach ($candidates as $candidate) {
            if (is_file($candidate)) {
                require_once $candidate;
                break;
            }
        }
    }
    if (!class_exists(\SecureNow\SecureNow::class)) {
        return;
    }

    try {
        \SecureNow\SecureNow::start();
        if (!\SecureNow\SecureNow::isStarted()) {
            return;
        }
        \SecureNow\SecureNow::setFramework('wordpress', isset($GLOBALS['wp_version']) ? (string) $GLOBALS['wp_version'] : null);
    } catch (\Throwable $e) {
        return;
    }

    // http.route: the REST route pattern, the admin screen, or the kind of page served.
    add_filter('rest_dispatch_request', static function ($result, $request, $route = '', $handler = null) {
        try {
            // $route is the matched pattern: /wp/v2/posts/(?P<id>[\d]+)
            if (is_string($route) && $route !== '') {
                \SecureNow\SecureNow::setRoute('/' . rest_get_url_prefix() . $route);
            }
        } catch (\Throwable $e) {
        }
        return $result;
    }, 10, 4);

    add_action('wp', static function (): void {
        try {
            if (is_admin() || (defined('REST_REQUEST') && REST_REQUEST)) {
                return;
            }
            $kind = 'page';
            if (is_front_page() || is_home()) {
                $kind = 'home';
            } elseif (is_singular()) {
                $kind = (string) get_post_type();
            } elseif (is_search()) {
                $kind = 'search';
            } elseif (is_404()) {
                $kind = '404';
            } elseif (is_archive()) {
                $kind = 'archive';
            } elseif (is_feed()) {
                $kind = 'feed';
            }
            \SecureNow\SecureNow::setAttribute('wordpress.template', $kind);
        } catch (\Throwable $e) {
        }
    });

    add_action('set_current_user', static function (): void {
        try {
            $id = function_exists('get_current_user_id') ? (int) get_current_user_id() : 0;
            if ($id > 0) {
                \SecureNow\SecureNow::setUser($id);
            }
        } catch (\Throwable $e) {
        }
    });

    if (\SecureNow\Config::bool('events.auth', true)) {
        add_action('wp_login', static function ($login, $user = null): void {
            $props = is_object($user) && isset($user->ID) ? ['userId' => (string) $user->ID] : [];
            \SecureNow\SecureNow::track('auth.login.success', $props);
        }, 10, 2);
        add_action('wp_login_failed', static function (): void {
            \SecureNow\SecureNow::track('auth.login.failure', ['severity' => 'warn']);
        });
        add_action('wp_logout', static function ($userId = 0): void {
            \SecureNow\SecureNow::track('auth.logout', $userId ? ['userId' => (string) $userId] : []);
        });
        add_action('after_password_reset', static function ($user = null): void {
            $props = is_object($user) && isset($user->ID) ? ['userId' => (string) $user->ID] : [];
            \SecureNow\SecureNow::track('auth.password_reset.completed', $props);
        });
        add_action('user_register', static function ($userId = 0): void {
            \SecureNow\SecureNow::track('auth.signup', $userId ? ['userId' => (string) $userId] : []);
        });
    }
})();
