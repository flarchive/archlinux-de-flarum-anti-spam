<?php

namespace ArchLinux\AntiSpam\Validator;

use Flarum\Foundation\ValidationException;
use Flarum\User\Event\Saving;
use Flarum\User\User;
use MaxMind\Db\Reader;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\String\UnicodeString;

class RegistrationHandler
{
    private readonly Reader $geoIpReader;

    public function __construct(
        private readonly Config $config,
        private readonly LoggerInterface $logger,
        GeoIpReaderFactory $geoIpReaderFactory
    ) {
        $this->geoIpReader = $geoIpReaderFactory->createReader();
    }

    public function handle(Saving $event): void
    {
        if ($event->user->exists) {
            return;
        }

        $score = 0;

        $userIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

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

        $userAgent = $this->getUserAgent();
        if ($userAgent) {
            if ($this->isUserAgentBlocked($userAgent)) {
                $score--;
            }
            if ($this->isUserAgentAllowed($userAgent)) {
                $score++;
            }
        }

        $emailDomain = $this->getEmailDomain($event->user);
        if ($emailDomain) {
            if ($this->isEmailDomainBlocked($emailDomain)) {
                $score--;
            }
            if ($this->isEmailDomainAllowed($emailDomain)) {
                $score++;
            }
        }

        $logContext = [
            'username' => $event->user->username ?? '-',
            'email' => $event->user->email ?? '-',
            'ip' => $userIp,
            'country' => $country ?? '-',
            'agent' => $userAgent ?? '-',
            'email_domain' => $emailDomain ?? '-',
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

    private function getCountry(string $ip): ?string
    {
        try {
            $response = $this->geoIpReader->get($ip);
            if (is_array($response) && isset($response['country']['iso_code'])) {
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

    private function getUserAgent(): ?UnicodeString
    {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        if (!$userAgent) {
            return null;
        }

        return new UnicodeString($userAgent);
    }

    private function isUserAgentBlocked(UnicodeString $userAgent): bool
    {
        return $userAgent->containsAny($this->config->getUserAgentBlockList());
    }

    private function isUserAgentAllowed(UnicodeString $userAgent): bool
    {
        return $userAgent->containsAny($this->config->getUserAgentAllowList());
    }

    private function getEmailDomain(User $user): ?UnicodeString
    {
        if (!$user->email) {
            return null;
        }

        return (new UnicodeString($user->email))->afterLast('@');
    }

    private function isEmailDomainBlocked(UnicodeString $emailDomain): bool
    {
        return $emailDomain->equalsTo($this->config->getEmailDomainBlockList());
    }

    private function isEmailDomainAllowed(UnicodeString $emailDomain): bool
    {
        return $emailDomain->equalsTo($this->config->getEmailDomainAllowList());
    }
}
