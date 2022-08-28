<?php

namespace ArchLinux\AntiSpam\Test\Validator;

use ArchLinux\AntiSpam\Validator\Config;
use ArchLinux\AntiSpam\Validator\GeoIpReaderFactory;
use ArchLinux\AntiSpam\Validator\RegistrationHandler;
use Flarum\Foundation\ValidationException;
use Flarum\User\Event\Saving;
use Flarum\User\User;
use MaxMind\Db\Reader;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class RegistrationHandlerTest extends TestCase
{
    /** @var Config|MockObject */
    private Config $config;

    /** @var Reader|MockObject */
    private Reader $geoIpReader;

    /** @var LoggerInterface|MockObject */
    private LoggerInterface $logger;

    public function setUp(): void
    {
        $this->config = $this->createMock(Config::class);
        $this->geoIpReader = $this->createMock(Reader::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        unset($_SERVER['REMOTE_ADDR']);
        unset($_SERVER['HTTP_USER_AGENT']);
    }

    private function createRegistrationHandler(): RegistrationHandler
    {
        $geoIpReaderFactory = $this->createMock(GeoIpReaderFactory::class);
        $geoIpReaderFactory
            ->expects($this->once())
            ->method('createReader')
            ->willReturn($this->geoIpReader);

        return new RegistrationHandler($this->config, $this->logger, $geoIpReaderFactory);
    }

    private function createSavingEvent(): Saving
    {
        $user = $this->createMock(User::class);
        $user->exists = false;
        return new Saving($user, $this->createMock(User::class), []);
    }

    public function testBlockByDefault(): void
    {
        $_SERVER['REMOTE_ADDR'] = '123.0.0.1';

        $this->logger
            ->expects($this->once())
            ->method('info');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Anti-Spam score: 0');
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testCountryCanBeBlocked(): void
    {
        $_SERVER['REMOTE_ADDR'] = '123.0.0.1';

        $this->config
            ->expects($this->once())
            ->method('getCountryBlockList')
            ->willReturn(['DE']);

        $this->geoIpReader
            ->expects($this->once())
            ->method('get')
            ->willReturn(['country' => ['iso_code' => 'DE']]);

        $this->logger
            ->expects($this->once())
            ->method('info');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Anti-Spam score: -1');
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testCountryCanBeAllowed(): void
    {
        $this->config
            ->expects($this->once())
            ->method('getCountryAllowList')
            ->willReturn(['DE']);

        $this->geoIpReader
            ->expects($this->once())
            ->method('get')
            ->willReturn(['country' => ['iso_code' => 'DE']]);

        $this->logger
            ->expects($this->never())
            ->method('info');

        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testRecoverIfCountryIsUnknown(): void
    {
        $_SERVER['REMOTE_ADDR'] = '123.0.0.1';

        $this->geoIpReader
            ->expects($this->once())
            ->method('get')
            ->willThrowException(new Reader\InvalidDatabaseException());

        $this->logger
            ->expects($this->once())
            ->method('info');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Anti-Spam score: 0');
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testUserAgentCanBeBlocked(): void
    {
        $_SERVER['REMOTE_ADDR'] = '123.0.0.1';

        $this->config
            ->expects($this->once())
            ->method('getUserAgentBlockList')
            ->willReturn(['Windows']);

        $this->logger
            ->expects($this->once())
            ->method('info');

        $_SERVER['HTTP_USER_AGENT'] = 'IE/11; Windows';
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Anti-Spam score: -1');
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testUserAgentCanBeAllowed(): void
    {
        $this->config
            ->expects($this->once())
            ->method('getUserAgentAllowList')
            ->willReturn(['Linux']);

        $this->logger
            ->expects($this->never())
            ->method('info');

        $_SERVER['HTTP_USER_AGENT'] = 'Firefox/120; Linux';
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testIpCanBeBlocked(): void
    {
        $this->config
            ->expects($this->once())
            ->method('getIpBlockList')
            ->willReturn(['123.0.0.0/8']);

        $this->logger
            ->expects($this->once())
            ->method('info');

        $_SERVER['REMOTE_ADDR'] = '123.0.0.1';
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Anti-Spam score: -1');
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testIpCanBeAllowed(): void
    {
        $this->config
            ->expects($this->once())
            ->method('getIpAllowList')
            ->willReturn(['127.0.0.0/8']);

        $this->logger
            ->expects($this->never())
            ->method('info');

        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testDebugLogging(): void
    {
        $this->config
            ->expects($this->once())
            ->method('getIpAllowList')
            ->willReturn(['127.0.0.0/8']);
        $this->config
            ->expects($this->once())
            ->method('isDebug')
            ->willReturn(true);

        $this->logger
            ->expects($this->once())
            ->method('debug');

        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testDebugLoggingCanBeDisabled(): void
    {
        $this->config
            ->expects($this->once())
            ->method('getIpAllowList')
            ->willReturn(['127.0.0.0/8']);
        $this->config
            ->expects($this->once())
            ->method('isDebug')
            ->willReturn(false);

        $this->logger
            ->expects($this->never())
            ->method('info');

        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }
}
