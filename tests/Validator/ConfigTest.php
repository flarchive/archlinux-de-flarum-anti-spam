<?php

namespace ArchLinux\AntiSpam\Test\Validator;

use ArchLinux\AntiSpam\Validator\Config;
use Flarum\Foundation\Config as FlarumConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class ConfigTest extends TestCase
{
    private FlarumConfig&MockObject $flarumConfig;

    public function setUp(): void
    {
        $this->flarumConfig = $this->createMock(FlarumConfig::class);
    }

    public function testEmptyDefaultConfig(): void
    {
        $config = new Config($this->flarumConfig);

        $this->assertFalse($config->isDebug());

        $this->assertEquals('/usr/share/GeoIP/GeoLite2-Country.mmdb', $config->getGeoIpDatabase());

        $this->assertContains('127.0.0.0/8', $config->getIpAllowList());
        $this->assertEquals([], $config->getIpBlockList());

        $this->assertEquals([], $config->getUserAgentAllowList());
        $this->assertEquals([], $config->getUserAgentBlockList());

        $this->assertEquals([], $config->getCountryAllowList());
        $this->assertEquals([], $config->getCountryBlockList());
    }

    public function testDebugDefaultsToFlarumConfig(): void
    {
        $this->flarumConfig
            ->expects($this->once())
            ->method('inDebugMode')
            ->willReturn(true);

        $config = new Config($this->flarumConfig);

        $this->assertTrue($config->isDebug());
    }

    public function testDebugCanBeEnabled(): void
    {
        $this->flarumConfig
            ->expects($this->once())
            ->method('offsetGet')
            ->with('anti_spam')
            ->willReturn(['debug' => true]);

        $config = new Config($this->flarumConfig);

        $this->assertTrue($config->isDebug());
    }

    #[DataProvider('providerConfigArrays')]
    public function testConfigArrays(string $key, string $getter): void
    {
        $this->flarumConfig
            ->expects($this->once())
            ->method('offsetGet')
            ->with('anti_spam')
            ->willReturn([$key => ['foo']]);

        $config = new Config($this->flarumConfig);

        $this->assertEquals(['foo'], $config->$getter());
    }

    #[DataProvider('providerConfigArrays')]
    public function testEmptyConfigArrays(string $key, string $getter): void
    {
        $this->flarumConfig
            ->expects($this->once())
            ->method('offsetGet')
            ->with('anti_spam')
            ->willReturn([$key => []]);

        $config = new Config($this->flarumConfig);

        $this->assertEquals([], $config->$getter());
    }

    /**
     * @return array<int, array<string>>
     */
    public static function providerConfigArrays(): array
    {
        return [
            ['ip_allowed', 'getIpAllowList'],
            ['ip_blocked', 'getIpBlockList'],
            ['user_agent_allowed', 'getUserAgentAllowList'],
            ['user_agent_blocked', 'getUserAgentBlockList'],
            ['country_allowed', 'getCountryAllowList'],
            ['country_blocked', 'getCountryBlockList'],
        ];
    }

    public function testGetGeoIpDatabase(): void
    {
        $this->flarumConfig
            ->expects($this->once())
            ->method('offsetGet')
            ->with('anti_spam')
            ->willReturn(['geoip_database' => 'foo']);

        $config = new Config($this->flarumConfig);

        $this->assertEquals('foo', $config->getGeoIpDatabase());
    }
}
