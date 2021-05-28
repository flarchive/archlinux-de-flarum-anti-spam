<?php

namespace ArchLinux\AntiSpam\Tests\Validator;

use ArchLinux\AntiSpam\Validator\GeoIpReaderFactory;
use ArchLinux\AntiSpam\Validator\RegistrationHandler;
use Flarum\Foundation\Config;
use Flarum\Foundation\ValidationException;
use Flarum\User\Event\Saving;
use Flarum\User\User;
use MaxMind\Db\Reader;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class RegistrationHandlerTest extends TestCase
{
    private RegistrationHandler $registrationHandler;

    /** @var Config|MockObject */
    private Config $config;

    /** @var Reader|MockObject */
    private Reader $geoIpReader;

    public function setUp(): void
    {
        $this->config = $this->createMock(Config::class);
        $this->geoIpReader = $this->createMock(Reader::class);
        unset($_SERVER['REMOTE_ADDR']);
        unset($_SERVER['HTTP_USER_AGENT']);
    }

    private function createRegistrationHandler(): RegistrationHandler
    {
        $logger = $this->createMock(LoggerInterface::class);
        $geoIpReaderFactory = $this->createMock(GeoIpReaderFactory::class);
        $geoIpReaderFactory
            ->expects($this->once())
            ->method('createReader')
            ->willReturn($this->geoIpReader);

        return new RegistrationHandler($this->config, $logger, $geoIpReaderFactory);
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

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Anti-Spam score: 0');
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testCountryCanBeBlocked(): void
    {
        $_SERVER['REMOTE_ADDR'] = '123.0.0.1';

        $this->config
            ->expects($this->once())
            ->method('offsetGet')
            ->with('anti_spam')
            ->willReturn(['country_blocked' => ['DE']]);

        $this->geoIpReader
            ->expects($this->once())
            ->method('get')
            ->willReturn(['country' => ['iso_code' => 'DE']]);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Anti-Spam score: -1');
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testCountryCanBeAllowed(): void
    {
        $this->config
            ->expects($this->once())
            ->method('offsetGet')
            ->with('anti_spam')
            ->willReturn(['country_allowed' => ['DE']]);

        $this->geoIpReader
            ->expects($this->once())
            ->method('get')
            ->willReturn(['country' => ['iso_code' => 'DE']]);

        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testRecoverIfCountryIsUnknown(): void
    {
        $_SERVER['REMOTE_ADDR'] = '123.0.0.1';

        $this->geoIpReader
            ->expects($this->once())
            ->method('get')
            ->willThrowException(new Reader\InvalidDatabaseException());

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Anti-Spam score: 0');
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testUserAgentCanBeBlocked(): void
    {
        $_SERVER['REMOTE_ADDR'] = '123.0.0.1';

        $this->config
            ->expects($this->once())
            ->method('offsetGet')
            ->with('anti_spam')
            ->willReturn(['user_agent_blocked' => ['Windows']]);

        $_SERVER['HTTP_USER_AGENT'] = 'IE/11; Windows';
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Anti-Spam score: -1');
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testUserAgentCanBeAllowed(): void
    {
        $this->config
            ->expects($this->once())
            ->method('offsetGet')
            ->with('anti_spam')
            ->willReturn(['user_agent_allowed' => ['Linux']]);

        $_SERVER['HTTP_USER_AGENT'] = 'Firefox/120; Linux';
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testIpCanBeBlocked(): void
    {
        $this->config
            ->expects($this->once())
            ->method('offsetGet')
            ->with('anti_spam')
            ->willReturn(['ip_blocked' => ['123.0.0.0/8']]);

        $_SERVER['REMOTE_ADDR'] = '123.0.0.1';
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Anti-Spam score: -1');
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }

    public function testIpCanBeAllowed(): void
    {
        $this->config
            ->expects($this->once())
            ->method('offsetGet')
            ->with('anti_spam')
            ->willReturn(['ip_allowed' => ['127.0.0.0/8']]);

        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $this->createRegistrationHandler()->handle($this->createSavingEvent());
    }
}
