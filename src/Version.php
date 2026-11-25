<?php

declare(strict_types=1);

namespace SecureNow;

final class Version
{
    public const SDK = '1.0.1';
    public const NAME = 'securenow-php';
    /**
     * The firewall API compares X-SecureNow-SDK-Version with npm `securenow` versions (Scraper
     * Shield user-agent rules need 8.27.0 or later). This SDK implements the 8.28 firewall
     * protocol; its own identity goes in X-SecureNow-SDK.
     */
    public const FIREWALL_PROTOCOL = '8.28.0';
}
