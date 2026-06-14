<?php

namespace ArchLinux\AntiSpam\Validator;

use Flarum\Foundation\Config as FlarumConfig;
use Illuminate\Support\Arr;

class Config
{
    private readonly string $geoIpDatabase;

    /** @var string[] */
    private readonly array $userAgentAllowList;

    /** @var string[] */
    private readonly array $userAgentBlockList;

    /** @var string[] */
    private readonly array $countryAllowList;

    /** @var string[] */
    private readonly array $countryBlockList;

    /** @var string[] */
    private readonly array $ipAllowList;

    /** @var string[] */
    private readonly array $ipBlockList;

    /** @var string[] */
    private readonly array $emailDomainAllowList;

    /** @var string[] */
    private readonly array $emailDomainBlockList;

    private readonly bool $debug;

    public function __construct(private readonly FlarumConfig $flarumConfig)
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

        $this->emailDomainAllowList = $this->getStringArray($antiSpamConfig, 'email_domain_allowed');
        $this->emailDomainBlockList = $this->getStringArray($antiSpamConfig, 'email_domain_blocked');

        $this->debug = (bool)Arr::get($antiSpamConfig, 'debug', $flarumConfig->inDebugMode());
    }

    /**
     * @return string[]|\ArrayAccess<string,string>
     */
    private function getAntiSpamConfig(): array|\ArrayAccess
    {
        $antiSpamConfig = $this->flarumConfig->offsetGet('anti_spam') ?? [];
        assert(is_array($antiSpamConfig) || $antiSpamConfig instanceof \ArrayAccess);
        return $antiSpamConfig; // @phpstan-ignore return.type
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
        return $value; // @phpstan-ignore return.type
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

    /**
     * @return string[]
     */
    public function getEmailDomainAllowList(): array
    {
        return $this->emailDomainAllowList;
    }

    /**
     * @return string[]
     */
    public function getEmailDomainBlockList(): array
    {
        return $this->emailDomainBlockList;
    }

    public function isDebug(): bool
    {
        return $this->debug;
    }
}
