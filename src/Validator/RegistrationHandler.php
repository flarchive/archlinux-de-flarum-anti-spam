<?php

namespace ArchLinux\AntiSpam\Validator;

use Flarum\Foundation\Config;
use Flarum\Foundation\ValidationException;
use Flarum\User\Event\Saving;
use MaxMind\Db\Reader;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\IpUtils;

class RegistrationHandler
{
    private Reader $geoIpReader;

    /** @var string[] */
    private array $userAgentAllowList = [];

    /** @var string[] */
    private array $userAgentBlockList = [];

    /** @var string[] */
    private array $countryAllowList = [];

    /** @var string[] */
    private array $countryBlockList = [];

    /** @var string[] */
    private array $ipAllowList = ['10.0.0.0/8', '127.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '::1/128'];

    /** @var string[] */
    private array $ipBlockList = [];

    private LoggerInterface $logger;

    public function __construct(Config $config, LoggerInterface $logger, GeoIpReaderFactory $geoIpReaderFactory)
    {
        $this->logger = $logger;

        $antiSpamConfig = $config->offsetGet('anti_spam');

        if (isset($antiSpamConfig['user_agent_allowed']) && $antiSpamConfig['user_agent_allowed']) {
            $this->userAgentAllowList = $antiSpamConfig['user_agent_allowed'];
        }
        if (isset($antiSpamConfig['user_agent_blocked']) && $antiSpamConfig['user_agent_blocked']) {
            $this->userAgentBlockList = $antiSpamConfig['user_agent_blocked'];
        }

        if (isset($antiSpamConfig['country_allowed']) && $antiSpamConfig['country_allowed']) {
            $this->countryAllowList = $antiSpamConfig['country_allowed'];
        }
        if (isset($antiSpamConfig['country_blocked']) && $antiSpamConfig['country_blocked']) {
            $this->countryBlockList = $antiSpamConfig['country_blocked'];
        }

        if (isset($antiSpamConfig['ip_allowed']) && $antiSpamConfig['ip_allowed']) {
            $this->ipAllowList = $antiSpamConfig['ip_allowed'];
        }
        if (isset($antiSpamConfig['ip_blocked']) && $antiSpamConfig['ip_blocked']) {
            $this->ipBlockList = $antiSpamConfig['ip_blocked'];
        }

        $this->geoIpReader = $geoIpReaderFactory->createReader();
    }

    public function handle(Saving $event): void
    {
        $score = 0;

        if (!$event->user->exists) {
            $userIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
            if ($userIp) {
                $country = $this->getCountry($userIp);
                if ($country) {
                    if ($this->isCountryBlocked($country)) {
                        $score--;
                    }
                    if ($this->isCountryAllowed($country)) {
                        $score++;
                    }
                }

                if ($this->isIpBlocked($userIp)) {
                    $score--;
                }
                if ($this->isIpAllowed($userIp)) {
                    $score++;
                }
            }

            $userAgent = $this->getUserAgent();
            if ($userAgent) {
                if ($this->isUserAgentBlocked($userAgent)) {
                    $score--;
                }
                if ($this->isUserAgentAllowed($userAgent)) {
                    $score++;
                }
            }

            if ($score < 1) {
                $this->logger->alert(
                    sprintf(
                        'Anti-Spam: Blocked user agent "%s" from %s with score %d',
                        $userAgent,
                        $country ?? '__',
                        $score
                    )
                );
                throw new ValidationException([sprintf('Anti-Spam score: %d', $score)]);
            }
        }
    }

    private function getCountry(string $ip): ?string
    {
        try {
            $response = $this->geoIpReader->get($ip);
            if (isset($response['country']['iso_code'])) {
                return $response['country']['iso_code'];
            }
        } catch (\Exception $e) {
            $this->logger->error($e->getMessage());
        }

        return null;
    }

    private function isCountryBlocked(string $country): bool
    {
        return in_array($country, $this->countryBlockList);
    }

    private function isCountryAllowed(string $country): bool
    {
        return in_array($country, $this->countryAllowList);
    }

    private function getUserAgent(): ?string
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? null;
    }

    private function isUserAgentBlocked(string $userAgent): bool
    {
        foreach ($this->userAgentBlockList as $subString) {
            if (stripos($userAgent, $subString) !== false) {
                return true;
            }
        }
        return false;
    }

    private function isUserAgentAllowed(string $userAgent): bool
    {
        foreach ($this->userAgentAllowList as $subString) {
            if (stripos($userAgent, $subString) !== false) {
                return true;
            }
        }
        return false;
    }

    private function isIpBlocked(string $ip): bool
    {
        return IpUtils::checkIp($ip, $this->ipBlockList);
    }

    private function isIpAllowed(string $ip): bool
    {
        return IpUtils::checkIp($ip, $this->ipAllowList);
    }
}
