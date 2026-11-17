<?php

namespace ArchLinux\AntiSpam\Test\Service;

use ArchLinux\AntiSpam\Service\StopForumSpamService;
use Flarum\Foundation\Paths;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class StopForumSpamServiceTest extends TestCase
{
    private Paths&MockObject $paths;
    private LoggerInterface&MockObject $logger;
    private Client&MockObject $http;
    private string $tempStorage;

    public function setUp(): void
    {
        $this->tempStorage = sys_get_temp_dir() . '/flarum-anti-spam-test-' . uniqid();
        mkdir($this->tempStorage . '/anti-spam', 0755, true);

        $this->paths = $this->createMock(Paths::class);
        $this->paths->method('__get')->with('storage')->willReturn($this->tempStorage);

        $this->logger = $this->createMock(LoggerInterface::class);
        $this->http = $this->createMock(Client::class);
    }

    public function tearDown(): void
    {
        $this->removeDirectory($this->tempStorage);
    }

    private function removeDirectory(string $path): void
    {
        $files = glob($path . '/*');
        if ($files === false) {
            return;
        }

        foreach ($files as $file) {
            is_dir($file) ? $this->removeDirectory($file) : unlink($file);
        }
        rmdir($path);
    }

    private function createService(): StopForumSpamService
    {
        return new StopForumSpamService($this->paths, $this->logger, $this->http);
    }

    public function testDownloadAndProcessLists(): void
    {
        $headers = ['Accept' => 'text/plain'];
        $responseHeaders = ['Content-Type' => 'text/plain'];

        $this->http->expects($this->exactly(4))
            ->method('get')
            ->willReturnMap([
                [
                    'https://www.stopforumspam.com/downloads/toxic_domains_whole_filtered_10000.txt',
                    ['connect_timeout' => 10, 'timeout' => 30, 'headers' => $headers],
                    new Response(200, $responseHeaders, str_repeat("spam.com\n", 20))
                ],
                [
                    'https://www.stopforumspam.com/downloads/toxic_domains_partial.txt',
                    ['connect_timeout' => 10, 'timeout' => 30, 'headers' => $headers],
                    new Response(200, $responseHeaders, str_repeat("bad-part\n", 20))
                ],
                [
                    'https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt',
                    ['connect_timeout' => 10, 'timeout' => 30, 'headers' => $headers],
                    new Response(200, $responseHeaders, str_repeat("1.2.3.4\n", 20))
                ],
                [
                    'https://www.stopforumspam.com/downloads/toxic_usernames_partial.txt',
                    ['connect_timeout' => 10, 'timeout' => 30, 'headers' => $headers],
                    new Response(200, $responseHeaders, str_repeat("spammer\n", 20))
                ],
            ]);

        $service = $this->createService();
        $this->assertTrue($service->downloadAndProcessLists());

        $this->assertFileExists($this->tempStorage . '/anti-spam/toxic_domains_whole.php');
        $this->assertFileExists($this->tempStorage . '/anti-spam/toxic_domains_partial.php');
        $this->assertFileExists($this->tempStorage . '/anti-spam/toxic_ip_cidr.php');
        $this->assertFileExists($this->tempStorage . '/anti-spam/toxic_usernames_partial.php');
    }

    public function testDownloadAndProcessListsFailsOnSanityCheck(): void
    {
        $this->http->method('get')->willReturn(new Response(200, ['Content-Type' => 'text/plain'], "too-few\n"));
        $this->logger->expects($this->atLeastOnce())
            ->method('error')
            ->with($this->stringContains('Sanity check failed'));

        $service = $this->createService();
        $this->assertFalse($service->downloadAndProcessLists());
    }

    public function testDownloadAndProcessListsFailsOnHttpError(): void
    {
        $this->http->method('get')->willReturn(new Response(500, [], "Internal Server Error"));
        $this->logger->expects($this->atLeastOnce())
            ->method('error')
            ->with($this->stringContains('Unexpected status code 500'));

        $service = $this->createService();
        $this->assertFalse($service->downloadAndProcessLists());
    }

    public function testDownloadAndProcessListsFailsOnWrongContentType(): void
    {
        $this->http->method('get')->willReturn(new Response(200, ['Content-Type' => 'text/html'], "<html></html>"));
        $this->logger->expects($this->atLeastOnce())
            ->method('error')
            ->with($this->stringContains('Unexpected Content-Type text/html'));

        $service = $this->createService();
        $this->assertFalse($service->downloadAndProcessLists());
    }

    public function testIsSpamDomainDetectsSpam(): void
    {
        $domains = ['spam.com' => true, 'another-spam.net' => true];
        file_put_contents(
            $this->tempStorage . '/anti-spam/toxic_domains_whole.php',
            "<?php return " . var_export($domains, true) . ";"
        );
        file_put_contents(
            $this->tempStorage . '/anti-spam/toxic_domains_partial.php',
            "<?php return [];"
        );

        $service = $this->createService();
        $this->assertTrue($service->isSpamDomain('spam.com'));
        $this->assertTrue($service->isSpamDomain('another-spam.net'));
        $this->assertFalse($service->isSpamDomain('safe.com'));
    }

    public function testIsSpamDomainDetectsPartialSpam(): void
    {
        file_put_contents(
            $this->tempStorage . '/anti-spam/toxic_domains_whole.php',
            "<?php return [];"
        );
        $partial = ['bad-part', '.spam-suffix.com'];
        file_put_contents(
            $this->tempStorage . '/anti-spam/toxic_domains_partial.php',
            "<?php return " . var_export($partial, true) . ";"
        );

        $service = $this->createService();
        $this->assertTrue($service->isSpamDomain('something-bad-part.com'));
        $this->assertTrue($service->isSpamDomain('user.spam-suffix.com'));
        $this->assertFalse($service->isSpamDomain('safe.com'));
    }

    public function testIsSpamUsernameDetectsSpam(): void
    {
        $usernames = ['spammer', 'bot'];
        file_put_contents(
            $this->tempStorage . '/anti-spam/toxic_usernames_partial.php',
            "<?php return " . var_export($usernames, true) . ";"
        );

        $service = $this->createService();
        $this->assertTrue($service->isSpamUsername('spammer123'));
        $this->assertTrue($service->isSpamUsername('my_bot_user'));
        $this->assertTrue($service->isSpamUsername('SPAMMER')); // case insensitive
        $this->assertFalse($service->isSpamUsername('real_user'));
    }

    public function testIsSpamIpDetectsSpam(): void
    {
        $ips = ['1.2.3.4', '5.6.7.0/24'];
        file_put_contents(
            $this->tempStorage . '/anti-spam/toxic_ip_cidr.php',
            "<?php return " . var_export($ips, true) . ";"
        );

        $service = $this->createService();
        $this->assertTrue($service->isSpamIp('1.2.3.4'));
        $this->assertTrue($service->isSpamIp('5.6.7.8'));
        $this->assertFalse($service->isSpamIp('1.2.3.5'));
        $this->assertFalse($service->isSpamIp('8.8.8.8'));
    }

    public function testIsSpamIpReturnsFalseIfFileMissing(): void
    {
        $this->logger->expects($this->once())->method('warning');

        $service = $this->createService();
        $this->assertFalse($service->isSpamIp('1.2.3.4'));
    }
}
