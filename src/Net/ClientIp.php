<?php

declare(strict_types=1);

namespace SecureNow\Net;

use SecureNow\Config;
use SecureNow\Http\RequestInfo;

/**
 * The real client address, with the Node SDK's trusted-proxy rules (resolve-ip.js): forwarding
 * headers count only when the direct connection comes from a private address, this host, or a
 * proxy listed in config.networking.trustedProxies. A client cannot choose its own address.
 */
final class ClientIp
{
    /** Cloudflare's published edge ranges: an app behind Cloudflare trusts them with "cloudflare". */
    private const PRESETS = [
        'cloudflare' => [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
            '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
            '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
            '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
            '2a06:98c0::/29', '2c0f:f248::/32',
        ],
    ];

    private static ?IpSet $trusted = null;
    private static bool $trustedLoaded = false;
    /** @var array<string,true>|null */
    private static ?array $hostIps = null;

    public static function reset(): void
    {
        self::$trusted = null;
        self::$trustedLoaded = false;
        self::$hostIps = null;
    }

    private static function trustedSet(): ?IpSet
    {
        if (self::$trustedLoaded) {
            return self::$trusted;
        }
        self::$trustedLoaded = true;
        $expanded = [];
        foreach (Config::list('networking.trustedProxies') as $entry) {
            $preset = self::PRESETS[strtolower($entry)] ?? null;
            if ($preset !== null) {
                foreach ($preset as $range) {
                    $expanded[] = $range;
                }
            } else {
                $expanded[] = strpos($entry, '/') !== false ? $entry : Ip::normalize($entry);
            }
        }
        self::$trusted = $expanded ? IpSet::fromList($expanded) : null;
        return self::$trusted;
    }

    /** @return array<string,true> this machine's own non-loopback addresses */
    public static function hostIps(): array
    {
        if (self::$hostIps !== null) {
            return self::$hostIps;
        }
        $ips = [];
        if (function_exists('apcu_fetch') && function_exists('apcu_enabled') && @apcu_enabled()) {
            $cached = @apcu_fetch('securenow:hostips');
            if (is_array($cached)) {
                return self::$hostIps = $cached;
            }
        }
        if (function_exists('net_get_interfaces')) {
            try {
                $interfaces = @net_get_interfaces();
                if (is_array($interfaces)) {
                    foreach ($interfaces as $interface) {
                        foreach (($interface['unicast'] ?? []) as $unicast) {
                            $address = Ip::normalize((string) ($unicast['address'] ?? ''));
                            if ($address !== '' && !Ip::isLoopback($address) && Ip::parse($address) !== null) {
                                $ips[$address] = true;
                            }
                        }
                    }
                }
            } catch (\Throwable $e) {
            }
        }
        if (function_exists('apcu_store') && function_exists('apcu_enabled') && @apcu_enabled()) {
            @apcu_store('securenow:hostips', $ips, 300);
        }
        return self::$hostIps = $ips;
    }

    public static function isFromTrustedProxy(string $socketIp): bool
    {
        $normalized = Ip::normalize($socketIp);
        if ($normalized === '') {
            return false;
        }
        $trusted = self::trustedSet();
        if ($trusted !== null && $trusted->contains($normalized)) {
            return true;
        }
        if (isset(self::hostIps()[$normalized])) {
            return true;
        }
        return Ip::isPrivate($normalized);
    }

    /**
     * @return array{ip:string,source:string,socketIp:string,trustedProxy:bool,forwardedFor:string,realIp:string,cfConnectingIp:string,trueClientIp:string,clientIp:string}
     */
    public static function resolve(RequestInfo $request): array
    {
        $raw = trim($request->remoteAddr);
        // PHP-FPM behind a web server on a Unix socket: only a process on this machine can connect.
        $viaLocalSocket = $raw === '' || strncmp($raw, 'unix:', 5) === 0 || $raw[0] === '/';
        $socketIp = $viaLocalSocket ? '' : Ip::normalize($raw);
        $trustedProxy = $viaLocalSocket || self::isFromTrustedProxy($socketIp);

        $details = [
            'ip' => $socketIp,
            'source' => $socketIp !== '' ? 'socket' : ($viaLocalSocket ? 'unix-socket' : 'unknown'),
            'socketIp' => $socketIp,
            'trustedProxy' => $trustedProxy,
            'forwardedFor' => $request->header('x-forwarded-for'),
            'realIp' => $request->header('x-real-ip'),
            'cfConnectingIp' => $request->header('cf-connecting-ip'),
            'trueClientIp' => $request->header('true-client-ip'),
            'clientIp' => $request->header('x-client-ip'),
        ];
        if (!$trustedProxy) {
            return $details;
        }

        $chain = [];
        foreach (explode(',', $details['forwardedFor']) as $part) {
            $ip = Ip::normalize($part);
            if ($ip !== '') {
                $chain[] = $ip;
            }
        }
        if ($chain) {
            for ($i = count($chain) - 1; $i >= 0; $i--) {
                if (!self::isFromTrustedProxy($chain[$i])) {
                    $details['ip'] = $chain[$i];
                    $details['source'] = 'x-forwarded-for';
                    return $details;
                }
            }
            return $details;
        }

        $candidates = [
            'cf-connecting-ip' => $details['cfConnectingIp'],
            'true-client-ip' => $details['trueClientIp'],
            'x-real-ip' => $details['realIp'],
            'x-client-ip' => $details['clientIp'],
        ];
        foreach ($candidates as $source => $value) {
            $ip = Ip::normalize($value);
            if ($ip !== '') {
                $details['ip'] = $ip;
                $details['source'] = $source;
                return $details;
            }
        }

        if (Ip::isLoopback($socketIp)) {
            // A localhost request without proxy headers is the app's own traffic.
            $details['source'] = 'loopback';
            return $details;
        }
        if (isset(self::hostIps()[$socketIp])) {
            $details['source'] = 'trusted-proxy-socket';
        }
        return $details;
    }
}
