<?php

namespace ArchLinux\AntiSpam\Service;

use Flarum\Foundation\Paths;
use GuzzleHttp\Client;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\IpUtils;

class StopForumSpamService
{
    private const STOP_FORUM_SPAM_URL = 'https://www.stopforumspam.com';
    private const DOMAIN_LIST_URL = self::STOP_FORUM_SPAM_URL . '/downloads/toxic_domains_whole_filtered_10000.txt';
    private const DOMAIN_PARTIAL_LIST_URL = self::STOP_FORUM_SPAM_URL . '/downloads/toxic_domains_partial.txt';
    private const IP_LIST_URL = self::STOP_FORUM_SPAM_URL . '/downloads/toxic_ip_cidr.txt';
    private const USERNAME_LIST_URL = self::STOP_FORUM_SPAM_URL . '/downloads/toxic_usernames_partial.txt';

    private const STORAGE_DIR = '/anti-spam';
    private const DOMAIN_FILE = 'toxic_domains_whole.php';
    private const DOMAIN_PARTIAL_FILE = 'toxic_domains_partial.php';
    private const IP_FILE = 'toxic_ip_cidr.php';
    private const USERNAME_FILE = 'toxic_usernames_partial.php';

    /** @var array<string, bool>|null */
    private ?array $domains = null;

    /** @var string[]|null */
    private ?array $partialDomains = null;

    /** @var string[]|null */
    private ?array $ips = null;

    /** @var string[]|null */
    private ?array $usernames = null;

    public function __construct(
        private readonly Paths $paths,
        private readonly LoggerInterface $logger,
        private readonly Client $http
    ) {
    }

    public function downloadAndProcessLists(): bool
    {
        $success = true;

        $success &= $this->downloadAndProcessList(self::DOMAIN_LIST_URL, self::DOMAIN_FILE, true);
        $success &= $this->downloadAndProcessList(self::DOMAIN_PARTIAL_LIST_URL, self::DOMAIN_PARTIAL_FILE, false);
        $success &= $this->downloadAndProcessList(self::IP_LIST_URL, self::IP_FILE, false);
        $success &= $this->downloadAndProcessList(self::USERNAME_LIST_URL, self::USERNAME_FILE, false);

        return (bool)$success;
    }

    private function downloadAndProcessList(string $url, string $filename, bool $asMap): bool
    {
        $this->logger->info(sprintf('Downloading StopForumSpam list from %s', $url));

        try {
            $response = $this->http->get($url, [
                'connect_timeout' => 10,
                'timeout' => 30,
                'headers' => [
                    'Accept' => 'text/plain',
                ],
            ]);

            if ($response->getStatusCode() !== 200) {
                $this->logger->error(
                    sprintf(
                        'Failed to download list from %s: Unexpected status code %d',
                        $url,
                        $response->getStatusCode()
                    )
                );
                return false;
            }

            $contentType = $response->getHeaderLine('Content-Type');
            if (!str_starts_with($contentType, 'text/plain')) {
                $this->logger->error(
                    sprintf(
                        'Failed to download list from %s: Unexpected Content-Type %s',
                        $url,
                        $contentType
                    )
                );
                return false;
            }

            $rawContent = (string)$response->getBody();
        } catch (\Exception $e) {
            $this->logger->error(sprintf('Failed to download list from %s: %s', $url, $e->getMessage()));
            return false;
        }

        $lines = array_filter(array_map('trim', explode("\n", $rawContent)), function ($line) {
            return !empty($line) && !str_starts_with($line, '#');
        });

        // Sanity Check: Ensure we have at least a few entries
        // Even the small lists (IP/Username) have ~50+ entries.
        if (count($lines) < 10) {
            $this->logger->error(
                sprintf(
                    'Sanity check failed for %s: too few entries (%d). Aborting update.',
                    $url,
                    count($lines)
                )
            );
            return false;
        }

        $data = [];
        foreach ($lines as $item) {
            $data[$item] = true;
        }

        // Convert to indexed array if we don't need a map for O(1) lookups
        if (!$asMap) {
            $data = array_keys($data);
        }

        $storagePath = $this->paths->storage . self::STORAGE_DIR;
        if (!is_dir($storagePath)) {
            mkdir($storagePath, 0755, true);
        }

        $targetFile = $storagePath . '/' . $filename;
        $fileContent = "<?php\n\nreturn " . var_export($data, true) . ";\n";

        if (file_put_contents($targetFile, $fileContent) === false) {
            $this->logger->error(sprintf('Failed to write list to %s', $targetFile));
            return false;
        }

        return true;
    }

    public function isSpamDomain(string $domain): bool
    {
        if ($this->domains === null) {
            /** @var array<string, bool> $list */
            $list = $this->loadList(self::DOMAIN_FILE) ?? [];
            $this->domains = $list;
        }

        if (isset($this->domains[$domain])) {
            return true;
        }

        if ($this->partialDomains === null) {
            /** @var string[] $list */
            $list = $this->loadList(self::DOMAIN_PARTIAL_FILE) ?? [];
            $this->partialDomains = $list;
        }

        $domain = mb_strtolower($domain);

        foreach ($this->partialDomains as $partial) {
            if (str_contains($domain, mb_strtolower($partial))) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<mixed>|null
     */
    private function loadList(string $filename): ?array
    {
        $path = $this->paths->storage . self::STORAGE_DIR . '/' . $filename;
        if (!file_exists($path)) {
            $this->logger->warning(
                sprintf(
                    'StopForumSpam list file %s does not exist. Run anti-spam:download-block-lists command.',
                    $path
                )
            );
            return null;
        }

        /** @var mixed $data */
        $data = include $path;

        return is_array($data) ? $data : null;
    }

    public function isSpamUsername(string $username): bool
    {
        if ($this->usernames === null) {
            /** @var string[] $list */
            $list = $this->loadList(self::USERNAME_FILE) ?? [];
            $this->usernames = $list;
        }

        $username = mb_strtolower($username);

        foreach ($this->usernames as $partial) {
            if (str_contains($username, mb_strtolower($partial))) {
                return true;
            }
        }

        return false;
    }

    public function isSpamIp(string $ip): bool
    {
        if ($this->ips === null) {
            /** @var string[] $list */
            $list = $this->loadList(self::IP_FILE) ?? [];
            $this->ips = $list;
        }

        if (empty($this->ips)) {
            return false;
        }

        return IpUtils::checkIp($ip, $this->ips);
    }
}
