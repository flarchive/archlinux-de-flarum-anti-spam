<?php

namespace ArchLinux\AntiSpam;

use ArchLinux\AntiSpam\Validator\RegistrationHandler;
use Flarum\Extend;
use Flarum\User\Event\Saving;

return [
    (new Extend\Event())->listen(Saving::class, RegistrationHandler::class),
];
