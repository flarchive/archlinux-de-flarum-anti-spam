<?php

namespace ArchLinux\AntiSpam\Validator;

use Flarum\Foundation\ValidationException;
use Flarum\User\Event\Saving;
use MaxMind\Db\Reader;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\IpUtils;

class RegistrationHandler
{
    private Reader $geoIpReader;

    public function __construct(
        private Config $config,
        private LoggerInterface $logger,
        GeoIpReaderFactory $geoIpReaderFactory
    ) {
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

            $logContext = [
                'username' => $event->user->username,
                'email' => $event->user->email,
                'ip' => $userIp ?? '-',
                'country' => $country ?? '-',
                'agent' => $userAgent ?? '-',
                'score' => $score
            ];

            if ($score < 1) {
                $this->logger->info('Anti-Spam blocked user registration', $logContext);
                throw new ValidationException(
                    ['anti-spam-message' => 'Registration blocked by Anti-Spam.'],
                    ['anti-spam-score' => sprintf('Anti-Spam score: %d', $score)]
                );
            } elseif ($this->config->isDebug()) {
                $this->logger->debug('Anti-Spam debug', $logContext);
            }
        }
    }

    private function getCountry(string $ip): ?string
    {
        try {
            $response = $this->geoIpReader->get($ip);
            if (is_array($response) && isset($response['country']) && isset($response['country']['iso_code'])) {
                return $response['country']['iso_code'];
            }
        } catch (\Exception $e) {
            $this->logger->error($e->getMessage());
        }

        return null;
    }

    private function isCountryBlocked(string $country): bool
    {
        return in_array($country, $this->config->getCountryBlockList());
    }

    private function isCountryAllowed(string $country): bool
    {
        return in_array($country, $this->config->getCountryAllowList());
    }

    private function isIpBlocked(string $ip): bool
    {
        return IpUtils::checkIp($ip, $this->config->getIpBlockList());
    }

    private function isIpAllowed(string $ip): bool
    {
        return IpUtils::checkIp($ip, $this->config->getIpAllowList());
    }

    private function getUserAgent(): ?string
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? null;
    }

    private function isUserAgentBlocked(string $userAgent): bool
    {
        foreach ($this->config->getUserAgentBlockList() as $subString) {
            if (stripos($userAgent, $subString) !== false) {
                return true;
            }
        }
        return false;
    }

    private function isUserAgentAllowed(string $userAgent): bool
    {
        foreach ($this->config->getUserAgentAllowList() as $subString) {
            if (stripos($userAgent, $subString) !== false) {
                return true;
            }
        }
        return false;
    }
}
