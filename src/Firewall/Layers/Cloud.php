<?php

declare(strict_types=1);

namespace SecureNow\Firewall\Layers;

use SecureNow\Config;
use SecureNow\Diag;
use SecureNow\Http\Transport;
use SecureNow\Net\Ip;
use SecureNow\Util;

/**
 * Layer 4: pushes the blocklist to the cloud WAF in front of the app, so blocked addresses are
 * stopped at the edge (the Node SDK's firewall-cloud.js). Providers: cloudflare, aws, gcp.
 * No cloud SDK is needed: each provider's REST API is called directly. Runs in
 * `vendor/bin/securenow agent`. Cloud credentials are never logged.
 *
 *   config.firewall.cloud = "cloudflare" | "aws" | "gcp";  cloudDryRun = true logs without pushing
 */
final class Cloud
{
    private const MIN_PUSH_INTERVAL = 30;
    private const GCP_BASE_PRIORITY = 2000;
    private const GCP_RANGES_PER_RULE = 10;
    private const GCP_MAX_RULES = 100;

    private string $provider;
    private int $lastPush = 0;
    private int $gcpRuleCount = 0;

    public function __construct(string $provider)
    {
        $this->provider = strtolower($provider);
    }

    public function init(): bool
    {
        if (!in_array($this->provider, ['cloudflare', 'aws', 'gcp'], true)) {
            Diag::warn('Firewall cloud: unknown provider "' . $this->provider . '", expected cloudflare|aws|gcp');
            return false;
        }
        return true;
    }

    /**
     * Blocklist entries as canonical CIDRs per family: an exact address becomes /32 or /128, an
     * IPv4-mapped address is IPv4, a range starts at its network address, and what a provider
     * would refuse (not an IP, a /0) is left out; the app still blocks those.
     *
     * @param string[] $ips
     * @return array{v4:string[],v6:string[]}
     */
    public static function toCidrs(array $ips): array
    {
        $v4 = [];
        $v6 = [];
        foreach ($ips as $raw) {
            $entry = trim((string) $raw);
            if ($entry === '') {
                continue;
            }
            if (strpos($entry, '/') === false) {
                $ip = Ip::parse($entry);
                if ($ip !== null) {
                    if ($ip['f'] === 4) {
                        $v4[$ip['key'] . '/32'] = true;
                    } else {
                        $v6[$ip['key'] . '/128'] = true;
                    }
                }
                continue;
            }
            $range = Ip::cidr($entry);
            if ($range === null || $range['bits'] === 0) {
                continue;
            }
            $network = inet_ntop($range['start']);
            if ($network === false) {
                continue;
            }
            if ($range['f'] === 4) {
                $v4[$network . '/' . $range['bits']] = true;
            } else {
                $v6[$network . '/' . $range['bits']] = true;
            }
        }
        return ['v4' => array_map('strval', array_keys($v4)), 'v6' => array_map('strval', array_keys($v6))];
    }

    /** @param string[] $ips */
    public function sync(array $ips, bool $force = false): bool
    {
        if (!$force && time() - $this->lastPush < self::MIN_PUSH_INTERVAL) {
            return false;
        }
        $this->lastPush = time();
        if (Config::bool('firewall.cloudDryRun', false)) {
            Diag::info('Firewall cloud: dry-run, would push ' . count($ips) . ' IPs to ' . $this->provider);
            return true;
        }
        try {
            if ($this->provider === 'cloudflare') {
                $this->cloudflare($ips);
            } elseif ($this->provider === 'aws') {
                $this->aws($ips);
            } else {
                $this->gcp($ips);
            }
            Diag::info('Firewall cloud: pushed ' . count($ips) . ' IPs to ' . $this->provider);
            return true;
        } catch (\Throwable $e) {
            Diag::warn('Firewall cloud: push to ' . $this->provider . ' failed: ' . $e->getMessage());
            return false;
        }
    }

    /** @param mixed $value */
    private static function setting(string $path, array $envNames, $default = null): ?string
    {
        $value = Config::get($path);
        if (is_string($value) && $value !== '') {
            return $value;
        }
        foreach ($envNames as $name) {
            $env = Config::env($name);
            if ($env !== null) {
                return $env;
            }
        }
        return is_string($default) ? $default : null;
    }

    // ---- Cloudflare ----

    /**
     * @param mixed $body
     * @return array<string,mixed>
     */
    private function cf(string $method, string $path, string $token, $body = null): array
    {
        $response = Transport::request(
            $method,
            'https://api.cloudflare.com/client/v4' . $path,
            ['authorization' => 'Bearer ' . $token, 'content-type' => 'application/json'],
            $body === null ? null : Util::json($body),
            15000
        );
        $data = json_decode($response['body'], true);
        if (!is_array($data)) {
            throw new \RuntimeException('Cloudflare answered HTTP ' . $response['status']);
        }
        if (($data['success'] ?? true) === false) {
            throw new \RuntimeException('Cloudflare: ' . Util::json($data['errors'] ?? 'request refused'));
        }
        return $data;
    }

    /** @param string[] $ips */
    private function cloudflare(array $ips): void
    {
        $token = self::setting('firewall.cloudflare.apiToken', ['CLOUDFLARE_API_TOKEN']);
        $account = self::setting('firewall.cloudflare.accountId', ['CLOUDFLARE_ACCOUNT_ID']);
        if ($token === null || $account === null) {
            throw new \RuntimeException('missing Cloudflare API token or account id');
        }
        $name = 'securenow-blocklist';
        $list = null;
        foreach (($this->cf('GET', "/accounts/$account/rules/lists", $token)['result'] ?? []) as $candidate) {
            if (($candidate['name'] ?? '') === $name) {
                $list = $candidate;
                break;
            }
        }
        if ($list === null) {
            $list = $this->cf('POST', "/accounts/$account/rules/lists", $token, [
                'name' => $name, 'kind' => 'ip', 'description' => 'Managed by SecureNow firewall SDK',
            ])['result'] ?? null;
        }
        if (!is_array($list) || empty($list['id'])) {
            throw new \RuntimeException('could not find or create the Cloudflare list');
        }
        // Cloudflare lists take IPv6 ranges of /64 or wider: narrower ones stay blocked in the app.
        $cidrs = self::toCidrs($ips);
        $items = [];
        foreach ($cidrs['v4'] as $cidr) {
            $items[] = ['ip' => $cidr];
        }
        $skipped = 0;
        foreach ($cidrs['v6'] as $cidr) {
            if ((int) substr($cidr, (int) strrpos($cidr, '/') + 1) <= 64) {
                $items[] = ['ip' => $cidr];
            } else {
                $skipped++;
            }
        }
        if ($skipped > 0) {
            Diag::info("Firewall cloud: $skipped IPv6 entries narrower than /64 not pushed to Cloudflare (blocked in the app)");
        }
        $this->cf('PUT', "/accounts/$account/rules/lists/{$list['id']}/items", $token, $items);
    }

    // ---- AWS WAF (wafv2 JSON API, SigV4) ----

    /** @return array{key:string,secret:string,token:?string} */
    private static function awsCredentials(): array
    {
        $key = self::setting('firewall.aws.accessKeyId', ['AWS_ACCESS_KEY_ID']);
        $secret = self::setting('firewall.aws.secretAccessKey', ['AWS_SECRET_ACCESS_KEY']);
        if ($key !== null && $secret !== null) {
            return ['key' => $key, 'secret' => $secret, 'token' => self::setting('firewall.aws.sessionToken', ['AWS_SESSION_TOKEN'])];
        }
        // EC2 instance role (IMDSv2).
        $token = Transport::request('PUT', 'http://169.254.169.254/latest/api/token', ['x-aws-ec2-metadata-token-ttl-seconds' => '60'], '', 800);
        if ($token['status'] === 200 && $token['body'] !== '') {
            $headers = ['x-aws-ec2-metadata-token' => $token['body']];
            $role = Transport::request('GET', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', $headers, null, 800);
            $name = trim(strtok($role['body'], "\n") ?: '');
            if ($role['status'] === 200 && $name !== '') {
                $creds = json_decode(Transport::request('GET', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' . rawurlencode($name), $headers, null, 800)['body'], true);
                if (is_array($creds) && !empty($creds['AccessKeyId']) && !empty($creds['SecretAccessKey'])) {
                    return ['key' => (string) $creds['AccessKeyId'], 'secret' => (string) $creds['SecretAccessKey'], 'token' => isset($creds['Token']) ? (string) $creds['Token'] : null];
                }
            }
        }
        throw new \RuntimeException('no AWS credentials (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, config.firewall.aws, or an instance role)');
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    private function wafv2(string $action, array $payload, string $region): array
    {
        $creds = self::awsCredentials();
        $host = "wafv2.$region.amazonaws.com";
        $body = Util::json($payload);
        $amzDate = gmdate('Ymd\THis\Z');
        $date = substr($amzDate, 0, 8);
        $headers = [
            'content-type' => 'application/x-amz-json-1.1',
            'host' => $host,
            'x-amz-date' => $amzDate,
            'x-amz-target' => 'AWSWAF_20190729.' . $action,
        ];
        if ($creds['token'] !== null) {
            $headers['x-amz-security-token'] = $creds['token'];
        }
        ksort($headers);
        $canonicalHeaders = '';
        foreach ($headers as $name => $value) {
            $canonicalHeaders .= $name . ':' . trim($value) . "\n";
        }
        $signedHeaders = implode(';', array_keys($headers));
        $canonical = "POST\n/\n\n$canonicalHeaders\n$signedHeaders\n" . hash('sha256', $body);
        $scope = "$date/$region/wafv2/aws4_request";
        $toSign = "AWS4-HMAC-SHA256\n$amzDate\n$scope\n" . hash('sha256', $canonical);
        $key = hash_hmac('sha256', $date, 'AWS4' . $creds['secret'], true);
        foreach ([$region, 'wafv2', 'aws4_request'] as $part) {
            $key = hash_hmac('sha256', $part, $key, true);
        }
        $signature = hash_hmac('sha256', $toSign, $key);
        unset($headers['host']);
        $headers['authorization'] = "AWS4-HMAC-SHA256 Credential={$creds['key']}/$scope, SignedHeaders=$signedHeaders, Signature=$signature";

        $response = Transport::request('POST', "https://$host/", $headers, $body, 15000);
        $data = json_decode($response['body'], true);
        if ($response['status'] !== 200 || !is_array($data)) {
            $message = is_array($data) ? (string) ($data['message'] ?? $data['Message'] ?? $data['__type'] ?? '') : (string) $response['error'];
            throw new \RuntimeException("AWS WAF $action failed (HTTP {$response['status']}) $message");
        }
        return $data;
    }

    /** @param string[] $ips */
    private function aws(array $ips): void
    {
        $id = self::setting('firewall.aws.wafIpSetId', ['AWS_WAF_IP_SET_ID']);
        if ($id === null) {
            throw new \RuntimeException('missing config.firewall.aws.wafIpSetId');
        }
        $name = self::setting('firewall.aws.wafIpSetName', ['AWS_WAF_IP_SET_NAME'], 'securenow-blocklist') ?? 'securenow-blocklist';
        $scope = strtoupper(self::setting('firewall.aws.wafScope', ['AWS_WAF_SCOPE'], 'REGIONAL') ?? 'REGIONAL');
        // CloudFront IP sets live in us-east-1.
        $region = $scope === 'CLOUDFRONT' ? 'us-east-1' : (self::setting('firewall.aws.region', ['AWS_REGION', 'AWS_DEFAULT_REGION']) ?? '');
        if ($region === '') {
            throw new \RuntimeException('missing AWS region (config.firewall.aws.region or AWS_REGION)');
        }
        $current = $this->wafv2('GetIPSet', ['Name' => $name, 'Scope' => $scope, 'Id' => $id], $region);
        // An IP set holds one address family: push the entries of the set's family.
        $cidrs = self::toCidrs($ips);
        $ipv6 = ($current['IPSet']['IPAddressVersion'] ?? 'IPV4') === 'IPV6';
        $other = $ipv6 ? count($cidrs['v4']) : count($cidrs['v6']);
        if ($other > 0) {
            Diag::info("Firewall cloud: $other " . ($ipv6 ? 'IPv4' : 'IPv6') . ' entries not pushed to this ' . ($ipv6 ? 'IPv6' : 'IPv4') . ' IP set (blocked in the app)');
        }
        $this->wafv2('UpdateIPSet', [
            'Name' => $name,
            'Scope' => $scope,
            'Id' => $id,
            'Addresses' => $ipv6 ? $cidrs['v6'] : $cidrs['v4'],
            'LockToken' => (string) ($current['LockToken'] ?? ''),
            'Description' => 'Managed by SecureNow firewall SDK',
        ], $region);
    }

    // ---- GCP Cloud Armor ----

    private static function gcpToken(): string
    {
        $token = self::setting('firewall.gcp.accessToken', ['GOOGLE_OAUTH_ACCESS_TOKEN', 'CLOUDSDK_AUTH_ACCESS_TOKEN']);
        if ($token !== null) {
            return $token;
        }
        // The service account of the VM, Cloud Run service or GKE workload.
        $response = Transport::request(
            'GET',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            ['metadata-flavor' => 'Google'],
            null,
            1500
        );
        $data = json_decode($response['body'], true);
        if ($response['status'] === 200 && is_array($data) && !empty($data['access_token'])) {
            return (string) $data['access_token'];
        }
        throw new \RuntimeException('no GCP access token (GOOGLE_OAUTH_ACCESS_TOKEN, config.firewall.gcp.accessToken, or the metadata server)');
    }

    /** @param string[] $ips */
    private function gcp(array $ips): void
    {
        $project = self::setting('firewall.gcp.projectId', ['GCP_PROJECT_ID', 'GOOGLE_CLOUD_PROJECT']);
        $policy = self::setting('firewall.gcp.securityPolicy', ['GCP_SECURITY_POLICY']);
        if ($project === null || $policy === null) {
            throw new \RuntimeException('missing config.firewall.gcp.projectId or securityPolicy');
        }
        $headers = ['authorization' => 'Bearer ' . self::gcpToken(), 'content-type' => 'application/json'];
        $base = 'https://compute.googleapis.com/compute/v1/projects/' . rawurlencode($project) . '/global/securityPolicies/' . rawurlencode($policy);

        // A Cloud Armor rule matches at most 10 ranges: the blocklist is spread over consecutive
        // rules from priority 2000, and rules left over from a longer blocklist are removed.
        $cidrs = self::toCidrs($ips);
        $all = array_merge($cidrs['v4'], $cidrs['v6']);
        $ranges = array_slice($all, 0, self::GCP_MAX_RULES * self::GCP_RANGES_PER_RULE);
        if (count($ranges) < count($all)) {
            Diag::info('Firewall cloud: Cloud Armor gets the first ' . count($ranges) . ' blocklist entries; the rest are blocked in the app');
        }
        $chunks = array_chunk($ranges, self::GCP_RANGES_PER_RULE);
        foreach ($chunks as $i => $chunk) {
            $priority = self::GCP_BASE_PRIORITY + $i;
            $rule = Util::json([
                'priority' => $priority,
                'action' => 'deny(403)',
                'match' => ['versionedExpr' => 'SRC_IPS_V1', 'config' => ['srcIpRanges' => $chunk]],
                'description' => 'Managed by SecureNow firewall SDK',
            ]);
            $response = Transport::request('POST', "$base/patchRule?priority=$priority", $headers, $rule, 15000);
            if ($response['status'] === 404 || ($response['status'] === 400 && stripos($response['body'], 'priority') !== false)) {
                $response = Transport::request('POST', "$base/addRule", $headers, $rule, 15000);
            }
            if ($response['status'] < 200 || $response['status'] >= 300) {
                throw new \RuntimeException('Cloud Armor rule ' . $priority . ' refused (HTTP ' . $response['status'] . ') ' . substr($response['body'], 0, 200));
            }
        }
        for ($i = count($chunks); $i < max($this->gcpRuleCount, 1); $i++) {
            $response = Transport::request('POST', "$base/removeRule?priority=" . (self::GCP_BASE_PRIORITY + $i), $headers, '', 15000);
            if ($response['status'] >= 300 && $response['status'] !== 404 && $response['status'] !== 400) {
                throw new \RuntimeException('Cloud Armor rule removal refused (HTTP ' . $response['status'] . ')');
            }
        }
        $this->gcpRuleCount = count($chunks);
    }
}
