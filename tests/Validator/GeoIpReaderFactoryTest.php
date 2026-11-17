<?php

namespace ArchLinux\AntiSpam\Test\Validator;

use ArchLinux\AntiSpam\Validator\Config;
use ArchLinux\AntiSpam\Validator\GeoIpReaderFactory;
use MaxMind\Db\Reader;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpClient\HttpClient;

class GeoIpReaderFactoryTest extends TestCase
{
    private const DATABASE_FILE = __DIR__ . '/test.mmdb';

    private const DATABASE_URL = 'https://github.com/maxmind/MaxMind-DB/raw/main/test-data/GeoIP2-Country-Test.mmdb';

    public function setUp(): void
    {
        $filesystem = new Filesystem();

        if ($filesystem->exists(self::DATABASE_FILE)) {
            return;
        }

        $filesystem->dumpFile(
            self::DATABASE_FILE,
            HttpClient::create()->request('GET', self::DATABASE_URL)->getContent()
        );
    }

    public function testCreateReader(): void
    {
        $config = $this->createMock(Config::class);
        $config
            ->expects($this->once())
            ->method('getGeoIpDatabase')
            ->willReturn(self::DATABASE_FILE);

        $geoIpReaderFactory = new GeoIpReaderFactory($config);
        $geoIpReader = $geoIpReaderFactory->createReader();

        $this->assertInstanceOf(Reader::class, $geoIpReader); // @phpstan-ignore method.alreadyNarrowedType
    }

    public function testGeoIpLookup(): void
    {
        $config = $this->createMock(Config::class);
        $config
            ->expects($this->once())
            ->method('getGeoIpDatabase')
            ->willReturn(self::DATABASE_FILE);

        $geoIpReaderFactory = new GeoIpReaderFactory($config);
        $geoIpReader = $geoIpReaderFactory->createReader();

        $record = $geoIpReader->get('2001:218::1');

        $this->assertIsArray($record);
        $this->assertArrayHasKey('country', $record);
        $this->assertIsArray($record['country']);
        $this->assertArrayHasKey('iso_code', $record['country']);
        $this->assertEquals('JP', $record['country']['iso_code']);
    }
}
