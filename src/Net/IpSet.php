<?php

declare(strict_types=1);

namespace SecureNow\Net;

/**
 * A set of IPv4/IPv6 addresses and CIDR ranges, kept as sorted, merged binary ranges: 8 bytes per
 * IPv4 range (first and last address), 32 bytes per IPv6 range. A lookup is a binary search, in
 * memory or straight from a file, so a request never loads a large blocklist into PHP arrays.
 */
final class IpSet
{
    public string $v4 = '';
    public string $v6 = '';
    /** @var array<string,true> entries that are not IP addresses, matched as written */
    public array $other = [];
    public int $exact = 0;
    public int $cidr = 0;

    /** @param iterable<mixed> $entries */
    public static function fromList(iterable $entries): self
    {
        $set = new self();
        $r4 = [];
        $r6 = [];
        foreach ($entries as $entry) {
            if (!is_string($entry)) {
                continue;
            }
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }
            if (strpos($entry, '/') !== false) {
                $range = Ip::cidr($entry);
                if ($range === null) {
                    continue;
                }
                $set->cidr++;
                if ($range['f'] === 4) {
                    $r4[] = $range['start'] . $range['end'];
                } else {
                    $r6[] = $range['start'] . $range['end'];
                }
                continue;
            }
            $set->exact++;
            $parsed = Ip::parse($entry);
            if ($parsed === null) {
                $set->other[$entry] = true;
            } elseif ($parsed['f'] === 4) {
                $r4[] = $parsed['bin'] . $parsed['bin'];
            } else {
                $r6[] = $parsed['bin'] . $parsed['bin'];
            }
        }
        $set->v4 = self::merge($r4, 4);
        $set->v6 = self::merge($r6, 16);
        return $set;
    }

    /**
     * @param string[] $ranges start+end records
     */
    private static function merge(array $ranges, int $width): string
    {
        if (!$ranges) {
            return '';
        }
        sort($ranges, SORT_STRING);
        $out = '';
        $curStart = substr($ranges[0], 0, $width);
        $curEnd = substr($ranges[0], $width);
        $n = count($ranges);
        for ($i = 1; $i < $n; $i++) {
            $start = substr($ranges[$i], 0, $width);
            $end = substr($ranges[$i], $width);
            if (strcmp($start, $curEnd) <= 0) {
                if (strcmp($end, $curEnd) > 0) {
                    $curEnd = $end;
                }
                continue;
            }
            $out .= $curStart . $curEnd;
            $curStart = $start;
            $curEnd = $end;
        }
        return $out . $curStart . $curEnd;
    }

    public function total(): int
    {
        return $this->exact + $this->cidr;
    }

    public function isEmpty(): bool
    {
        return $this->v4 === '' && $this->v6 === '' && !$this->other;
    }

    public function contains(?string $ip): bool
    {
        if ($ip === null || $ip === '') {
            return false;
        }
        $parsed = Ip::parse($ip);
        if ($parsed === null) {
            return isset($this->other[trim($ip)]);
        }
        return $parsed['f'] === 4
            ? self::searchString($this->v4, 4, $parsed['bin'])
            : self::searchString($this->v6, 16, $parsed['bin']);
    }

    /** Binary search over packed start+end records: the last record that starts at or before the key. */
    public static function searchString(string $data, int $width, string $key): bool
    {
        $record = $width * 2;
        $lo = 0;
        $hi = intdiv(strlen($data), $record) - 1;
        while ($lo <= $hi) {
            $mid = ($lo + $hi) >> 1;
            $offset = $mid * $record;
            if (strcmp(substr($data, $offset, $width), $key) <= 0) {
                if (strcmp($key, substr($data, $offset + $width, $width)) <= 0) {
                    return true;
                }
                $lo = $mid + 1;
            } else {
                $hi = $mid - 1;
            }
        }
        return false;
    }

    /** The same search, reading the records from a file. */
    public static function searchFile(string $file, int $width, string $key): bool
    {
        $handle = @fopen($file, 'rb');
        if ($handle === false) {
            return false;
        }
        try {
            $stat = fstat($handle);
            $record = $width * 2;
            $lo = 0;
            $hi = intdiv((int) ($stat['size'] ?? 0), $record) - 1;
            while ($lo <= $hi) {
                $mid = ($lo + $hi) >> 1;
                if (fseek($handle, $mid * $record) !== 0) {
                    return false;
                }
                $row = fread($handle, $record);
                if ($row === false || strlen($row) !== $record) {
                    return false;
                }
                if (strcmp(substr($row, 0, $width), $key) <= 0) {
                    if (strcmp($key, substr($row, $width)) <= 0) {
                        return true;
                    }
                    $lo = $mid + 1;
                } else {
                    $hi = $mid - 1;
                }
            }
            return false;
        } finally {
            fclose($handle);
        }
    }

    /** @return array{v4:string,v6:string,other:array<string,true>,exact:int,cidr:int} */
    public function export(): array
    {
        return ['v4' => $this->v4, 'v6' => $this->v6, 'other' => $this->other, 'exact' => $this->exact, 'cidr' => $this->cidr];
    }

    /** @param array<string,mixed>|null $data */
    public static function import(?array $data): self
    {
        $set = new self();
        if ($data) {
            $set->v4 = is_string($data['v4'] ?? null) ? $data['v4'] : '';
            $set->v6 = is_string($data['v6'] ?? null) ? $data['v6'] : '';
            $set->other = is_array($data['other'] ?? null) ? $data['other'] : [];
            $set->exact = (int) ($data['exact'] ?? 0);
            $set->cidr = (int) ($data['cidr'] ?? 0);
        }
        return $set;
    }
}
