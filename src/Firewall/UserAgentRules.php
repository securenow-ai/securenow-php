<?php

declare(strict_types=1);

namespace SecureNow\Firewall;

use SecureNow\Net\IpSet;

/**
 * Scraper Shield user-agent rules (firewall-ua.js). Scrapers that name themselves rotate
 * addresses, so the API sends the user agents to block and the firewall refuses them whatever
 * address they come from. Patterns are untrusted input: each is checked once, at sync, and one
 * that could backtrack catastrophically or does not compile is skipped. Allow patterns win.
 */
final class UserAgentRules
{
    private const MAX_RULES = 500;
    private const MAX_ALLOW = 300;
    private const MAX_PATTERN_LENGTH = 512;
    private const MAX_ID_LENGTH = 64;
    private const MAX_CATEGORY_LENGTH = 64;
    private const MAX_EXEMPT_ENTRIES = 10000;
    private const MAX_TESTED_UA = 4096;
    private const COMBINE = 40;

    /** Why a user-agent pattern is refused, or '' when it is safe to compile. */
    public static function patternProblem(string $pattern): string
    {
        $length = strlen($pattern);
        if ($length === 0) {
            return 'empty';
        }
        if ($length > self::MAX_PATTERN_LENGTH) {
            return 'longer than ' . self::MAX_PATTERN_LENGTH . ' characters';
        }
        $groups = [];
        $inClass = false;
        $closed = null;
        $unboundedCount = 0;

        for ($i = 0; $i < $length; $i++) {
            $c = $pattern[$i];
            if ($c === '\\') {
                if ($i + 1 >= $length) {
                    return 'ends with a backslash';
                }
                $next = $pattern[$i + 1];
                if (!$inClass && $next >= '1' && $next <= '9') {
                    return 'backreference';
                }
                if (!$inClass && $next === 'k' && ($pattern[$i + 2] ?? '') === '<') {
                    return 'backreference';
                }
                $i++;
                $closed = null;
                continue;
            }
            if ($inClass) {
                if ($c === ']') {
                    $inClass = false;
                }
                continue;
            }
            if ($c === '[') {
                $inClass = true;
                $closed = null;
                continue;
            }
            if ($c === '(') {
                if (($pattern[$i + 1] ?? '') === '?') {
                    $kind = $pattern[$i + 2] ?? '';
                    if ($kind === '=' || $kind === '!') {
                        return 'lookaround';
                    }
                    $after = $pattern[$i + 3] ?? '';
                    if ($kind === '<' && ($after === '=' || $after === '!')) {
                        return 'lookaround';
                    }
                    // PCRE-only constructs (recursion, conditionals, inline flags, atomic groups) are not
                    // valid in the API's JavaScript patterns: refuse them rather than guess.
                    if ($kind !== ':' && $kind !== '<') {
                        return 'unsupported group';
                    }
                    $i++;
                }
                $groups[] = ['unbounded' => false, 'repeating' => false, 'alternation' => false];
                $closed = null;
                continue;
            }
            if ($c === ')') {
                $group = array_pop($groups);
                if ($group === null) {
                    return 'unbalanced parenthesis';
                }
                $top = count($groups) - 1;
                if ($top >= 0) {
                    $groups[$top]['unbounded'] = $groups[$top]['unbounded'] || $group['unbounded'];
                    $groups[$top]['repeating'] = $groups[$top]['repeating'] || $group['repeating'];
                    $groups[$top]['alternation'] = $groups[$top]['alternation'] || $group['alternation'];
                }
                $closed = $group;
                continue;
            }
            if ($c === '|') {
                $top = count($groups) - 1;
                if ($top >= 0) {
                    $groups[$top]['alternation'] = true;
                }
                $closed = null;
                continue;
            }

            $qLength = 0;
            $unbounded = false;
            $repeats = false;
            if ($c === '*' || $c === '+') {
                $qLength = 1;
                $unbounded = true;
                $repeats = true;
            } elseif ($c === '?') {
                $qLength = 1;
            } elseif ($c === '{' && preg_match('/\G\{(\d+)(,(\d*))?\}/', $pattern, $m, 0, $i)) {
                $qLength = strlen($m[0]);
                $hasComma = isset($m[2]) && $m[2] !== '';
                if ($hasComma) {
                    $upperText = $m[3] ?? '';
                    $unbounded = $upperText === '';
                    $repeats = $unbounded || (int) $upperText > 1;
                } else {
                    $repeats = (int) $m[1] > 1;
                }
            }

            if ($qLength > 0) {
                if ($closed !== null) {
                    if ($closed['unbounded']) {
                        return 'nested quantifier';
                    }
                    if ($repeats && $closed['repeating']) {
                        return 'nested quantifier';
                    }
                    if ($repeats && $closed['alternation']) {
                        return 'repeated alternation';
                    }
                }
                if ($unbounded) {
                    $unboundedCount++;
                }
                $top = count($groups) - 1;
                if ($top >= 0) {
                    if ($unbounded) {
                        $groups[$top]['unbounded'] = true;
                    }
                    if ($repeats) {
                        $groups[$top]['repeating'] = true;
                    }
                }
                $i += $qLength - 1;
                // A lazy or possessive quantifier is still one quantifier.
                $after = $pattern[$i + 1] ?? '';
                if ($after === '?' || $after === '+') {
                    $i++;
                }
                $closed = null;
                continue;
            }
            $closed = null;
        }

        if ($inClass) {
            return 'unterminated character class';
        }
        if ($groups) {
            return 'unbalanced parenthesis';
        }
        if (@preg_match(Paths::delimit($pattern, 'i'), '') === false) {
            return 'invalid';
        }
        if ($unboundedCount > 1) {
            return 'more than one unbounded quantifier';
        }
        return '';
    }

    /**
     * @param mixed $list
     * @return array{0:array<int,array{id:string,pattern:string,category:string}>,1:int}
     */
    private static function compileEntries($list, int $max): array
    {
        $entries = [];
        $seen = [];
        $skipped = 0;
        foreach (is_array($list) ? $list : [] as $raw) {
            if (count($entries) >= $max || !is_array($raw)) {
                $skipped++;
                continue;
            }
            $id = is_string($raw['id'] ?? null) ? trim($raw['id']) : '';
            $pattern = is_string($raw['pattern'] ?? null) ? $raw['pattern'] : '';
            if ($id === '' || strlen($id) > self::MAX_ID_LENGTH || isset($seen[$id]) || self::patternProblem($pattern) !== '') {
                $skipped++;
                continue;
            }
            $seen[$id] = true;
            $category = is_string($raw['category'] ?? null) ? substr(trim($raw['category']), 0, self::MAX_CATEGORY_LENGTH) : '';
            $entries[] = ['id' => $id, 'pattern' => $pattern, 'category' => $category];
        }
        return [$entries, $skipped];
    }

    /**
     * The rules of one sync answer, checked and ready to store.
     *
     * @param mixed $payload { rules: [{id, pattern, category}], allow: [{id, pattern}], exemptIps: [...] }
     * @return array{rules:array<int,array{id:string,pattern:string,category:string}>,allow:array<int,array{id:string,pattern:string,category:string}>,exempt:array<string,mixed>,combined:string[],fingerprint:string,skipped:int}
     */
    public static function compile($payload): array
    {
        $list = [];
        $allowList = [];
        $exemptIps = [];
        if (is_array($payload)) {
            if (isset($payload['rules']) || isset($payload['allow']) || isset($payload['exemptIps'])) {
                $list = $payload['rules'] ?? [];
                $allowList = $payload['allow'] ?? [];
                $exemptIps = $payload['exemptIps'] ?? [];
            } elseif (\SecureNow\Util::isList($payload)) {
                $list = $payload;
            }
        }
        [$rules, $skippedRules] = self::compileEntries($list, self::MAX_RULES);
        [$allow, $skippedAllow] = self::compileEntries($allowList, self::MAX_ALLOW);

        $exempt = [];
        foreach (is_array($exemptIps) ? $exemptIps : [] as $entry) {
            if (count($exempt) >= self::MAX_EXEMPT_ENTRIES) {
                break;
            }
            if (is_string($entry) && trim($entry) !== '') {
                $exempt[] = trim($entry);
            }
        }

        // One alternation per group of rules: a browser's user agent is cleared in a handful of
        // matches instead of one per rule. A group that does not compile is tested rule by rule.
        $combined = [];
        foreach (array_chunk($rules, self::COMBINE) as $chunk) {
            $parts = [];
            foreach ($chunk as $rule) {
                $parts[] = '(?:' . $rule['pattern'] . ')';
            }
            $regex = Paths::delimit(implode('|', $parts), 'i');
            $combined[] = @preg_match($regex, '') === false ? '' : $regex;
        }

        return [
            'rules' => $rules,
            'allow' => $allow,
            'exempt' => IpSet::fromList($exempt)->export(),
            'combined' => $combined,
            'fingerprint' => sha1(serialize([$rules, $exempt, $allow])),
            'skipped' => $skippedRules + $skippedAllow,
        ];
    }

    /**
     * The first rule whose pattern matches the user agent, unless an allow pattern matches it too
     * or the address is exempt.
     *
     * @param array<string,mixed>|null $compiled
     * @return array{id:string,pattern:string,category:string}|null
     */
    public static function match(?array $compiled, string $userAgent, string $ip): ?array
    {
        if (!$compiled || empty($compiled['rules']) || $userAgent === '') {
            return null;
        }
        $tested = strlen($userAgent) > self::MAX_TESTED_UA ? substr($userAgent, 0, self::MAX_TESTED_UA) : $userAgent;
        $found = null;
        $chunks = array_chunk($compiled['rules'], self::COMBINE);
        foreach ($chunks as $index => $chunk) {
            $combined = $compiled['combined'][$index] ?? '';
            if ($combined !== '' && @preg_match($combined, $tested) !== 1) {
                continue;
            }
            foreach ($chunk as $rule) {
                if (@preg_match(Paths::delimit($rule['pattern'], 'i'), $tested) === 1) {
                    $found = $rule;
                    break 2;
                }
            }
        }
        if ($found === null) {
            return null;
        }
        foreach ($compiled['allow'] ?? [] as $entry) {
            if (@preg_match(Paths::delimit($entry['pattern'], 'i'), $tested) === 1) {
                return null;
            }
        }
        if ($ip !== '' && !empty($compiled['exempt']) && IpSet::import($compiled['exempt'])->contains($ip)) {
            return null;
        }
        return $found;
    }
}
