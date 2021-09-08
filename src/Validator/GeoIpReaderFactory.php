<?php

namespace ArchLinux\AntiSpam\Validator;

use Flarum\Foundation\Config;
use MaxMind\Db\Reader;

class GeoIpReaderFactory
{
    private string $geoIpDatabase = '/usr/share/GeoIP/GeoLite2-Country.mmdb';

    public function __construct(Config $config)
    {
        $antiSpamConfig = $config->offsetGet('anti_spam');
        if (isset($antiSpamConfig['geoip_database']) && $antiSpamConfig['geoip_database']) {
            $this->geoIpDatabase = $antiSpamConfig['geoip_database'];
        }
    }

    public function createReader(): Reader
    {
        return new Reader($this->geoIpDatabase);
    }
}
