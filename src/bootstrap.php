<?php

declare(strict_types=1);

/*
 * Loaded by Composer's autoloader (composer.json "autoload.files"), which every PHP framework
 * requires at the top of its entry file. This is SecureNow's zero-code start, the counterpart of
 * `node -r securenow/register`: the firewall answers before the framework boots, and the request
 * span opens here.
 *
 * It does nothing without credentials (.securenow/runtime.json or SECURENOW_CREDENTIALS), when
 * SECURENOW_DISABLED=1 or SECURENOW_AUTOSTART=0, and in plain CLI commands.
 * It never throws into the app.
 *
 * When auto_prepend_file already started the SDK (prepend.php), this second pass only finishes
 * what needed Composer's autoloader: the OpenTelemetry bridge.
 */

try {
    \SecureNow\SecureNow::autostart();
} catch (\Throwable $e) {
    @error_log('[securenow] start failed: ' . $e->getMessage());
}
