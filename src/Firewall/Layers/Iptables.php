<?php

declare(strict_types=1);

namespace SecureNow\Firewall\Layers;

use SecureNow\Diag;

/**
 * Layer 3: OS-level firewall via iptables (IPv4), ip6tables (IPv6) or, where neither exists,
 * nftables (the Node SDK's firewall-iptables.js). It manages its own chain (SECURENOW_BLOCK), or
 * with nft its own table: it never touches other rules. Linux only, needs root or CAP_NET_ADMIN.
 *
 * It runs in `vendor/bin/securenow agent`, not in web requests: PHP-FPM workers are not root.
 * Blocklist entries arrive over the network, so each one must be a literal IP or CIDR before it
 * reaches a firewall command, the binaries run without a shell, and a sync is one batch.
 */
final class Iptables
{
    public const CHAIN = 'SECURENOW_BLOCK';
    public const NFT_TABLE = 'securenow';

    private bool $active = false;
    private ?string $backend = null;
    private bool $ip6 = false;
    private int $maxRules;

    public function __construct(int $maxRules = 10000)
    {
        $this->maxRules = $maxRules;
    }

    /**
     * @param string[] $command
     * @return array{0:int,1:string} exit code and output
     */
    private static function run(array $command, ?string $input = null): array
    {
        $process = @proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) {
            return [127, 'cannot start ' . $command[0]];
        }
        if ($input !== null) {
            fwrite($pipes[0], $input);
        }
        fclose($pipes[0]);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($process), trim($out . $err)];
    }

    /** @param string[] $command */
    private static function succeeds(array $command, ?string $input = null): bool
    {
        return self::run($command, $input)[0] === 0;
    }

    /** A literal IPv4/IPv6 address or CIDR, or null. @return array{family:int,value:string}|null */
    public static function parseEntry(string $raw): ?array
    {
        $entry = trim($raw);
        $slash = strpos($entry, '/');
        $address = $slash === false ? $entry : substr($entry, 0, $slash);
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $family = 4;
        } elseif (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            $family = 6;
        } else {
            return null;
        }
        if ($slash !== false) {
            $bits = substr($entry, $slash + 1);
            if (!preg_match('/^\d{1,3}$/', $bits) || (int) $bits > ($family === 4 ? 32 : 128)) {
                return null;
            }
        }
        return ['family' => $family, 'value' => $entry];
    }

    /**
     * @param string[] $ips
     * @return array{v4:string[],v6:string[],rejected:int}
     */
    public static function splitFamilies(array $ips): array
    {
        $v4 = [];
        $v6 = [];
        $rejected = 0;
        foreach ($ips as $raw) {
            $parsed = is_string($raw) ? self::parseEntry($raw) : null;
            if ($parsed === null) {
                $rejected++;
                continue;
            }
            if ($parsed['family'] === 4) {
                $v4[] = $parsed['value'];
            } else {
                $v6[] = $parsed['value'];
            }
        }
        return ['v4' => $v4, 'v6' => $v6, 'rejected' => $rejected];
    }

    /** Input for iptables-restore --noflush: replaces the chain's rules in one step. @param string[] $entries */
    public static function restoreScript(array $entries): string
    {
        $lines = ['*filter', ':' . self::CHAIN . ' - [0:0]', '-F ' . self::CHAIN];
        foreach ($entries as $entry) {
            $lines[] = '-A ' . self::CHAIN . ' -s ' . $entry . ' -j DROP';
        }
        $lines[] = 'COMMIT';
        $lines[] = '';
        return implode("\n", $lines);
    }

    /** One nft -f transaction. @param string[] $v4 @param string[] $v6 */
    public static function nftScript(array $v4, array $v6): string
    {
        $lines = [
            'table inet ' . self::NFT_TABLE,
            'delete table inet ' . self::NFT_TABLE,
            'table inet ' . self::NFT_TABLE . ' {',
            '  chain input {',
            '    type filter hook input priority -10; policy accept;',
        ];
        foreach ($v4 as $entry) {
            $lines[] = '    ip saddr ' . $entry . ' drop';
        }
        foreach ($v6 as $entry) {
            $lines[] = '    ip6 saddr ' . $entry . ' drop';
        }
        $lines[] = '  }';
        $lines[] = '}';
        $lines[] = '';
        return implode("\n", $lines);
    }

    private static function setupChain(string $binary): bool
    {
        self::run([$binary, '-N', self::CHAIN]); // may already exist
        if (!self::succeeds([$binary, '-C', 'INPUT', '-j', self::CHAIN])) {
            return self::succeeds([$binary, '-I', 'INPUT', '1', '-j', self::CHAIN]);
        }
        return true;
    }

    public function init(): bool
    {
        if (PHP_OS_FAMILY !== 'Linux') {
            Diag::warn('Firewall iptables: only supported on Linux, skipping');
            return false;
        }
        if (!function_exists('proc_open')) {
            Diag::warn('Firewall iptables: proc_open is disabled, skipping');
            return false;
        }
        if (self::succeeds(['iptables', '--version'])) {
            $this->backend = 'iptables';
        } elseif (self::succeeds(['nft', '--version'])) {
            $this->backend = 'nft';
        } else {
            Diag::warn('Firewall iptables: neither iptables nor nft found, skipping');
            return false;
        }
        if ($this->backend === 'nft') {
            $this->active = self::succeeds(['nft', '-f', '-'], self::nftScript([], []));
        } else {
            $this->active = self::setupChain('iptables');
            if ($this->active && self::succeeds(['ip6tables', '--version'])) {
                $this->ip6 = self::setupChain('ip6tables');
            }
        }
        if (!$this->active) {
            Diag::warn('Firewall iptables: setup failed (need root or CAP_NET_ADMIN)');
            return false;
        }
        Diag::info('Firewall iptables: ' . ($this->backend === 'nft' ? 'nftables table ' . self::NFT_TABLE : 'iptables chain ' . self::CHAIN) . ' ready'
            . ($this->backend === 'iptables' && !$this->ip6 ? ' (IPv4 only: no ip6tables)' : ''));
        return true;
    }

    /** @param string[] $ips */
    public function sync(array $ips): void
    {
        if (!$this->active) {
            return;
        }
        if (count($ips) > $this->maxRules) {
            Diag::warn('Firewall iptables: truncated to ' . $this->maxRules . ' rules');
            $ips = array_slice($ips, 0, $this->maxRules);
        }
        $split = self::splitFamilies($ips);
        if ($split['rejected'] > 0) {
            Diag::warn('Firewall iptables: ignored ' . $split['rejected'] . ' blocklist entries that are not IPs or CIDRs');
        }
        if ($this->backend === 'nft') {
            $ok = self::succeeds(['nft', '-f', '-'], self::nftScript($split['v4'], $split['v6']));
        } else {
            $ok = self::succeeds(['iptables-restore', '--noflush'], self::restoreScript($split['v4']));
            if ($this->ip6) {
                $ok = self::succeeds(['ip6tables-restore', '--noflush'], self::restoreScript($split['v6'])) && $ok;
            }
        }
        if (!$ok) {
            Diag::warn('Firewall iptables: sync failed');
        } else {
            Diag::info('Firewall iptables: ' . (count($split['v4']) + count($split['v6'])) . ' addresses dropped at the OS firewall');
        }
    }

    public function shutdown(): void
    {
        if (!$this->active) {
            return;
        }
        if ($this->backend === 'nft') {
            self::run(['nft', 'delete', 'table', 'inet', self::NFT_TABLE]);
        } else {
            foreach ($this->ip6 ? ['iptables', 'ip6tables'] : ['iptables'] as $binary) {
                self::run([$binary, '-D', 'INPUT', '-j', self::CHAIN]);
                self::run([$binary, '-F', self::CHAIN]);
                self::run([$binary, '-X', self::CHAIN]);
            }
        }
        $this->active = false;
        Diag::info('Firewall iptables: cleaned up');
    }
}
