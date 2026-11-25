<?php

declare(strict_types=1);

namespace SecureNow\Events;

use SecureNow\Config;
use SecureNow\SecureNow;
use SecureNow\Telemetry\Exporter;
use SecureNow\Util;

/**
 * SecureNow custom security events (the Node SDK's securenow/events):
 *
 *   SecureNow::track('auth.login.failure', ['userId' => $id, 'attributes' => ['method' => 'password']]);
 *
 * Never throws, never slows the request: events are queued and sent after the response with the
 * rest of the telemetry. Inside a request, ip and userAgent default to the request's, with the
 * address resolved like the firewall's (X-Forwarded-For cannot choose it).
 */
final class Events
{
    /** @param array<string,mixed> $props userId, sessionId, ip, userAgent, severity, ts, attributes */
    public static function track(string $type, array $props = []): void
    {
        try {
            if ($type === '' || Config::disabled() || Config::appKey() === null) {
                return;
            }
            $event = ['type' => $type, 'ts' => isset($props['ts']) && is_numeric($props['ts']) ? (int) $props['ts'] : Util::nowMs()];
            if (isset($props['userId']) && is_scalar($props['userId'])) {
                $event['user_id'] = (string) $props['userId'];
            }
            if (isset($props['sessionId']) && is_scalar($props['sessionId'])) {
                $event['session_id'] = (string) $props['sessionId'];
            }
            if (isset($props['ip']) && is_scalar($props['ip'])) {
                $event['ip'] = (string) $props['ip'];
            }
            if (isset($props['userAgent']) && is_scalar($props['userAgent'])) {
                $event['user_agent'] = (string) $props['userAgent'];
            }
            if (!empty($props['severity']) && is_scalar($props['severity'])) {
                $event['severity'] = (string) $props['severity'];
            }
            if (isset($props['attributes']) && is_array($props['attributes']) && !Util::isList($props['attributes'])) {
                $event['attributes'] = $props['attributes'];
            }
            if (!isset($event['ip'])) {
                $ip = SecureNow::clientIp();
                if ($ip !== '') {
                    $event['ip'] = $ip;
                }
            }
            if (!isset($event['user_agent'])) {
                $ua = SecureNow::userAgent();
                if ($ua !== '') {
                    $event['user_agent'] = $ua;
                }
            }
            Exporter::addEvent($event);
        } catch (\Throwable $e) {
            // Events are advisory: never throw into the app.
        }
    }
}
