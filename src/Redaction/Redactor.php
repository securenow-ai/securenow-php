<?php

declare(strict_types=1);

namespace SecureNow\Redaction;

use SecureNow\Util;

/**
 * Redaction of captured request data and exported log lines. The same rules as the Node SDK
 * (otp-redaction.js, request-capture.js, header-redaction.js, log-redaction.js): credential
 * fields by name, then secret shapes (JWTs, Bearer/Basic credentials, API keys, emails, card
 * numbers) in values. Every pattern is linear and bounded.
 */
final class Redactor
{
    public const MARK = '[REDACTED]';
    private const MAX_VALUE_SCAN = 16384;
    public const MAX_LOG_SCAN = 262144;

    /** Matched exactly after case/separator normalization: "code" as a substring would hide status_code. */
    public const OTP_FIELDS = [
        'code', 'otp', 'otpCode', 'oneTimeCode', 'oneTimePassword', 'passcode',
        'verificationCode', 'confirmationCode', 'emailCode', 'smsCode', 'loginCode',
        'signInCode', 'authCode', 'authenticationCode', 'mfaCode', 'totpCode', '2faCode',
        'securityCode', 'recoveryCode', 'backupCode',
    ];

    /** Matched as lower-case substrings of the key: 'card' also catches 'creditCard'. */
    public const SENSITIVE_FIELDS = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'access_token', 'auth', 'authorization', 'bearer', 'credentials',
        'mysql_pwd', 'otp', 'mfa', 'totp', 'sessionid', 'session_id',
        'cookie', 'set-cookie',
        'stripeToken', 'card', 'cardnumber', 'ccv', 'cvc', 'cvv',
        'iban', 'account', 'accountnumber', 'routing', 'sortcode', 'taxid',
        'ssn', 'pin', 'email', 'e_mail', 'phone', 'mobile', 'dob', 'birthdate',
        'firstname', 'lastname', 'fullname', 'address', 'postcode', 'zip',
        'passport', 'license',
    ];

    private const HEADER_EXACT = ['cookie' => true, 'set-cookie' => true, 'authorization' => true, 'proxy-authorization' => true];
    private const HEADER_FRAGMENTS = [
        'token', 'secret', 'password', 'passwd', 'csrf', 'xsrf', 'session', 'api-key', 'apikey',
        'api_key', 'credential', 'signature', 'private-key', 'x-auth',
    ];

    private const LOG_CREDENTIAL_KEYS = [
        'password', 'passwd', 'pwd', 'passphrase', 'secret', 'clientsecret', 'privatekey',
        'token', 'accesstoken', 'refreshtoken', 'idtoken', 'sessiontoken', 'authtoken', 'bearer',
        'apikey', 'xapikey', 'authorization', 'cookie', 'setcookie', 'sessionid',
        'otp', 'otpcode', 'onetimecode', 'onetimepassword', 'passcode', 'verificationcode',
        'confirmationcode', 'mfacode', 'totpcode', '2facode', 'smscode', 'emailcode', 'logincode',
        'securitycode', 'recoverycode', 'backupcode',
        'cardnumber', 'cvv', 'cvc', 'ccv', 'ssn', 'pin',
    ];

    /** Query parameters whose values never reach a span (signed URLs), besides OTP codes. */
    private const REDACTED_QUERY_PARAMS = [
        'sig' => true, 'Signature' => true, 'AWSAccessKeyId' => true, 'X-Goog-Signature' => true,
        'X-Amz-Signature' => true, 'X-Amz-Credential' => true, 'X-Amz-Security-Token' => true,
    ];

    /** @var array<string,true>|null */
    private static ?array $otpNames = null;
    /** @var array<string,true>|null */
    private static ?array $logKeys = null;

    /** @var string[] lower-case fragments in use for this request */
    private array $fragments;
    /** @var string[] canonical custom fields, for header names */
    private array $customCanonical;

    /** @param string[] $customFields config.capture.sensitiveFields */
    public function __construct(array $customFields = [])
    {
        $fragments = [];
        foreach (array_merge(self::OTP_FIELDS, self::SENSITIVE_FIELDS, $customFields) as $field) {
            $field = (string) $field;
            if ($field === '') {
                continue;
            }
            // OTP aliases match exactly (isOtpCodeField); only "otp" itself also matches as a fragment.
            if (self::canonical($field) === 'otp' || !self::isOtpCodeField($field)) {
                $fragments[strtolower($field)] = true;
            }
        }
        $this->fragments = array_map('strval', array_keys($fragments));
        $this->customCanonical = array_values(array_filter(array_map([self::class, 'canonical'], $customFields)));
    }

    public static function canonical(string $key): string
    {
        return strtolower(preg_replace('/[^a-z0-9]/i', '', $key) ?? $key);
    }

    public static function isOtpCodeField(string $key): bool
    {
        if (self::$otpNames === null) {
            self::$otpNames = [];
            foreach (self::OTP_FIELDS as $field) {
                self::$otpNames[self::canonical($field)] = true;
            }
        }
        $name = preg_replace('/^http\.(?:request|response)\.headers?\./i', '', $key) ?? $key;
        if (preg_match('/(?:\[|\.)([^\[\].]+)\]?$/', $name, $m)) {
            $name = $m[1];
        }
        $name = preg_replace('/^x[-_]/i', '', $name) ?? $name;
        return isset(self::$otpNames[self::canonical($name)]);
    }

    public function isSensitiveField(string $key): bool
    {
        if (self::isOtpCodeField($key)) {
            return true;
        }
        $lower = strtolower($key);
        foreach ($this->fragments as $fragment) {
            if (strpos($lower, $fragment) !== false) {
                return true;
            }
        }
        return false;
    }

    public function isSensitiveHeader(string $name): bool
    {
        $lower = strtolower($name);
        if (isset(self::HEADER_EXACT[$lower])) {
            return true;
        }
        foreach (self::HEADER_FRAGMENTS as $fragment) {
            if (strpos($lower, $fragment) !== false) {
                return true;
            }
        }
        if (self::isOtpCodeField($lower)) {
            return true;
        }
        $canonical = self::canonical($lower);
        foreach ($this->customCanonical as $field) {
            if (strpos($canonical, $field) !== false) {
                return true;
            }
        }
        return false;
    }

    /** code: "123456" in GraphQL-style text. */
    public static function redactOtpGraphQL(string $query): string
    {
        if (strpos($query, ':') === false) {
            return $query;
        }
        $out = preg_replace_callback(
            '/\b([A-Za-z_][\w]*)(\s*:\s*)("(?:\\\\.|[^"\\\\])*"|\'(?:\\\\.|[^\'\\\\])*\'|[^\s,})]+)/',
            static function (array $m): string {
                return self::isOtpCodeField($m[1]) ? $m[1] . $m[2] . '"' . self::MARK . '"' : $m[0];
            },
            $query
        );
        return $out ?? $query;
    }

    /** ?code=123456: keeps every other byte of the query exactly as received. */
    public static function redactOtpQuery(string $value, string $marker = 'REDACTED'): string
    {
        if (strpos($value, '?') === false) {
            return $value;
        }
        $out = preg_replace_callback(
            '/([?&])([^?&#=\s]+)=([^&#\s]*)/',
            static function (array $m) use ($marker): string {
                $key = rawurldecode(str_replace('+', ' ', $m[2]));
                return self::isOtpCodeField($key) ? $m[1] . $m[2] . '=' . $marker : $m[0];
            },
            $value
        );
        return $out ?? $value;
    }

    /** "?a=1&sig=..." with signature-style and OTP parameter values replaced. */
    public static function redactSearch(string $search): string
    {
        if (strlen($search) < 2 || $search[0] !== '?') {
            return $search;
        }
        $changed = false;
        $parts = explode('&', substr($search, 1));
        foreach ($parts as $i => $part) {
            $eq = strpos($part, '=');
            $rawKey = $eq === false ? $part : substr($part, 0, $eq);
            $key = rawurldecode(str_replace('+', ' ', $rawKey));
            if (isset(self::REDACTED_QUERY_PARAMS[$key]) || self::isOtpCodeField($key)) {
                $parts[$i] = $rawKey . '=REDACTED';
                $changed = true;
            }
        }
        return $changed ? '?' . implode('&', $parts) : $search;
    }

    private static function luhnValid(string $digits): bool
    {
        $sum = 0;
        $alt = false;
        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
            $d = ord($digits[$i]) - 48;
            if ($d < 0 || $d > 9) {
                return false;
            }
            if ($alt) {
                $d *= 2;
                if ($d > 9) {
                    $d -= 9;
                }
            }
            $sum += $d;
            $alt = !$alt;
        }
        return $sum % 10 === 0;
    }

    /** Secret and PII shapes inside a string value. Returns the input when nothing matches. */
    public static function redactValue(string $value, int $maxScan = self::MAX_VALUE_SCAN): string
    {
        if ($value === '') {
            return $value;
        }
        $value = self::redactOtpQuery(self::redactOtpGraphQL($value));
        if (strlen($value) > $maxScan) {
            return $value;
        }
        $out = $value;
        if (strpos($out, 'eyJ') !== false) {
            $out = self::replace('/(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}/', $out);
        }
        if (stripos($out, 'bearer') !== false || stripos($out, 'basic') !== false) {
            $out = self::replace('/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+\/=-]{8,}/i', $out);
        }
        if (strpos($out, '_live_') !== false || strpos($out, '_test_') !== false) {
            $out = self::replace('/\b(?:sk|pk|rk|snk)_(?:live|test)_[A-Za-z0-9]{8,}/', $out);
        }
        if (strpos($out, '@') !== false) {
            $out = self::replace('/(?<![\w.%+-])[\w.%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/', $out);
        }
        if (preg_match('/\d{4}/', $out)) {
            $replaced = preg_replace_callback(
                '/\b(?:\d[ -]?){12,18}\d\b/',
                static function (array $m): string {
                    $digits = str_replace([' ', '-'], '', $m[0]);
                    $n = strlen($digits);
                    if ($n < 13 || $n > 19) {
                        return $m[0];
                    }
                    return self::luhnValid($digits) ? self::MARK : $m[0];
                },
                $out
            );
            $out = $replaced ?? '[REDACTION_ERROR]';
        }
        return $out;
    }

    private static function replace(string $pattern, string $subject): string
    {
        $out = preg_replace($pattern, self::MARK, $subject);
        // A failed scan (PCRE limit) never exports the raw value.
        return $out ?? '[REDACTION_ERROR]';
    }

    /**
     * Decoded JSON (objects as stdClass, arrays as lists) with sensitive fields and value shapes redacted.
     *
     * @param mixed $data
     * @return mixed
     */
    public function redactData($data, int $depth = 0)
    {
        if ($depth > 32) {
            return self::MARK;
        }
        if (is_object($data)) {
            $out = new \stdClass();
            foreach (get_object_vars($data) as $key => $value) {
                $key = (string) $key;
                if ($this->isSensitiveField($key)) {
                    $out->{$key} = self::MARK;
                } elseif (is_object($value) || is_array($value)) {
                    $out->{$key} = $this->redactData($value, $depth + 1);
                } elseif (is_string($value)) {
                    $out->{$key} = self::redactValue($value);
                } else {
                    $out->{$key} = $value;
                }
            }
            return $out;
        }
        if (is_array($data)) {
            $out = [];
            foreach ($data as $key => $value) {
                if (is_string($key) && $this->isSensitiveField($key)) {
                    $out[$key] = self::MARK;
                } elseif (is_object($value) || is_array($value)) {
                    $out[$key] = $this->redactData($value, $depth + 1);
                } elseif (is_string($value)) {
                    $out[$key] = self::redactValue($value);
                } else {
                    $out[$key] = $value;
                }
            }
            return $out;
        }
        return $data;
    }

    public function redactGraphQL(string $query): string
    {
        $redacted = $query;
        foreach ($this->fragments as $field) {
            $escaped = preg_quote($field, '/');
            if (stripos($redacted, $field) === false) {
                continue;
            }
            // Quoted values keep their quotes; then unquoted values (variables, numbers).
            $redacted = preg_replace('/(' . $escaped . '\s*:\s*["\'])([^"\']+)(["\'])/i', '$1' . self::MARK . '$3', $redacted) ?? $redacted;
            $redacted = preg_replace('/(' . $escaped . '\s*:\s*)([^\s,})\n"\'][^\s,})\n]*)/i', '$1' . self::MARK, $redacted) ?? $redacted;
        }
        return self::redactOtpGraphQL(self::redactValue($redacted));
    }

    /**
     * A captured body by content type. Null when the type is not captured.
     *
     * @return array{body:string,type:string}|null
     * @throws \JsonException when a JSON body does not parse
     */
    public function redactBodyText(string $body, string $contentType): ?array
    {
        $ct = strtolower($contentType);
        if (strpos($ct, 'application/graphql') !== false) {
            return ['body' => $this->redactGraphQL($body), 'type' => 'graphql'];
        }
        if (strpos($ct, 'application/json') !== false) {
            $parsed = json_decode($body, false, 64, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
            return ['body' => Util::json($this->redactData($parsed)), 'type' => 'json'];
        }
        if (strpos($ct, 'application/x-www-form-urlencoded') !== false) {
            $fields = new \stdClass();
            foreach (explode('&', $body) as $pair) {
                if ($pair === '') {
                    continue;
                }
                $eq = strpos($pair, '=');
                $key = urldecode($eq === false ? $pair : substr($pair, 0, $eq));
                $fields->{$key} = $eq === false ? '' : urldecode(substr($pair, $eq + 1));
            }
            return ['body' => Util::json($this->redactData($fields)), 'type' => 'form'];
        }
        return null;
    }

    private static function isCredentialKey(string $key, string $value): bool
    {
        if (self::$logKeys === null) {
            self::$logKeys = array_fill_keys(self::LOG_CREDENTIAL_KEYS, true);
        }
        $name = self::canonical($key);
        if (isset(self::$logKeys[$name])) {
            return true;
        }
        return $name === 'code' && preg_match('/^\d{4,8}$/', $value) === 1;
    }

    /** A log line: "password": "x" (JSON) and password=x (key=value), then secret shapes anywhere. */
    public static function redactLogText(string $text): string
    {
        if (strpos($text, '"') !== false) {
            $text = preg_replace_callback(
                '/"([A-Za-z0-9_-]{1,40})"(\s*:\s*)"((?:[^"\\\\]|\\\\.)*)"/',
                static function (array $m): string {
                    return ($m[3] !== '' && self::isCredentialKey($m[1], $m[3])) ? '"' . $m[1] . '"' . $m[2] . '"' . self::MARK . '"' : $m[0];
                },
                $text
            ) ?? $text;
        }
        if (strpos($text, '=') !== false) {
            $text = preg_replace_callback(
                '/(^|[\s,;&?{(])([A-Za-z0-9_-]{1,40})=([^\s&,;)}]+)/',
                static function (array $m): string {
                    return self::isCredentialKey($m[2], $m[3]) ? $m[1] . $m[2] . '=' . self::MARK : $m[0];
                },
                $text
            ) ?? $text;
        }
        return self::redactValue($text, self::MAX_LOG_SCAN);
    }

    /**
     * Log context (PSR-3 context arrays): credential fields replaced, nested arrays followed.
     *
     * @param mixed $value
     * @return mixed
     */
    public static function redactLogContext($value, int $depth = 0)
    {
        if (!is_array($value) || $depth > 8) {
            return $value;
        }
        $out = [];
        foreach ($value as $key => $item) {
            if (is_string($key) && is_scalar($item) && $item !== '' && self::isCredentialKey($key, (string) $item)) {
                $out[$key] = self::MARK;
            } else {
                $out[$key] = self::redactLogContext($item, $depth + 1);
            }
        }
        return $out;
    }
}
