<?php

namespace ArchLinux\AntiSpam\Validator;

use Flarum\Foundation\Config as FlarumConfig;
use Illuminate\Support\Arr;

class Config
{
    private string $geoIpDatabase;

    /** @var string[] */
    private array $userAgentAllowList;

    /** @var string[] */
    private array $userAgentBlockList;

    /** @var string[] */
    private array $countryAllowList;

    /** @var string[] */
    private array $countryBlockList;

    /** @var string[] */
    private array $ipAllowList;

    /** @var string[] */
    private array $ipBlockList;

    private bool $debug;

    public function __construct(private FlarumConfig $flarumConfig)
    {
        $antiSpamConfig = $this->getAntiSpamConfig();

        $this->geoIpDatabase = $this->getString(
            $antiSpamConfig,
            'geoip_database',
            '/usr/share/GeoIP/GeoLite2-Country.mmdb'
        );

        $this->userAgentAllowList = $this->getStringArray($antiSpamConfig, 'user_agent_allowed');
        $this->userAgentBlockList = $this->getStringArray($antiSpamConfig, 'user_agent_blocked');

        $this->countryAllowList = $this->getStringArray($antiSpamConfig, 'country_allowed');
        $this->countryBlockList = $this->getStringArray($antiSpamConfig, 'country_blocked');

        $this->ipAllowList = $this->getStringArray(
            $antiSpamConfig,
            'ip_allowed',
            ['10.0.0.0/8', '127.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '::1/128']
        );
        $this->ipBlockList = $this->getStringArray($antiSpamConfig, 'ip_blocked');

        $this->debug = (bool)Arr::get($antiSpamConfig, 'debug', $flarumConfig->inDebugMode());
    }

    /**
     * @return string[]|\ArrayAccess<string,string>
     */
    private function getAntiSpamConfig(): array|\ArrayAccess
    {
        $antiSpamConfig = $this->flarumConfig->offsetGet('anti_spam') ?? [];
        assert(is_array($antiSpamConfig) || $antiSpamConfig instanceof \ArrayAccess);
        return $antiSpamConfig;
    }

    /**
     * @param string[]|\ArrayAccess<string,string> $array
     * @param string $key
     * @param string $default
     * @return string
     */
    private function getString(array|\ArrayAccess $array, string $key, string $default = ''): string
    {
        $value = Arr::get($array, $key, $default);
        assert(is_string($value));
        return $value;
    }

    /**
     * @param string[]|\ArrayAccess<string,string> $array
     * @param string $key
     * @param string[] $default
     * @return string[]
     */
    private function getStringArray(array|\ArrayAccess $array, string $key, array $default = []): array
    {
        $value = Arr::get($array, $key, $default);
        assert(is_array($value));
        return $value;
    }

    /**
     * @return string[]
     */
    public function getUserAgentAllowList(): array
    {
        return $this->userAgentAllowList;
    }

    /**
     * @return string[]
     */
    public function getUserAgentBlockList(): array
    {
        return $this->userAgentBlockList;
    }

    /**
     * @return string[]
     */
    public function getCountryAllowList(): array
    {
        return $this->countryAllowList;
    }

    /**
     * @return string[]
     */
    public function getCountryBlockList(): array
    {
        return $this->countryBlockList;
    }

    public function getGeoIpDatabase(): string
    {
        return $this->geoIpDatabase;
    }

    /**
     * @return string[]
     */
    public function getIpAllowList(): array
    {
        return $this->ipAllowList;
    }

    /**
     * @return string[]
     */
    public function getIpBlockList(): array
    {
        return $this->ipBlockList;
    }

    public function isDebug(): bool
    {
        return $this->debug;
    }
}
