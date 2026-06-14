<?php

namespace ArchLinux\AntiSpam;

use ArchLinux\AntiSpam\Console\CheckAgainstStopForumSpamBlockLists;
use ArchLinux\AntiSpam\Console\DownloadStopForumSpamBlockLists;
use ArchLinux\AntiSpam\Validator\RegistrationHandler;
use Flarum\Extend;
use Flarum\User\Event\Saving;
use Flarum\Extension\Extension;
use Flarum\Foundation\Paths;
use Flarum\Frontend\Document;
use Illuminate\Console\Scheduling\Event;
use Illuminate\Contracts\Container\Container;

return [
    (new Extend\Event())->listen(Saving::class, RegistrationHandler::class),
    (new Extend\Console())
        ->command(DownloadStopForumSpamBlockLists::class)
        ->schedule(DownloadStopForumSpamBlockLists::class, function (Event $event) {
            $event->withoutOverlapping();
            $event->dailyAt(sprintf('%02d:%02d', rand(0, 5), rand(0, 59)));
        })
        ->command(CheckAgainstStopForumSpamBlockLists::class),
];
