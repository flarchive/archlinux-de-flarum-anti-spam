<?php

namespace ArchLinux\AntiSpam\Console;

use ArchLinux\AntiSpam\Service\StopForumSpamService;
use ArchLinux\AntiSpam\Validator\Config;
use Flarum\Console\AbstractCommand;
use Symfony\Component\Console\Command\Command;

class DownloadStopForumSpamBlockLists extends AbstractCommand
{
    public function __construct(
        private readonly StopForumSpamService $stopForumSpamService,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('anti-spam:download-block-lists')->setDescription('Download StopForumSpam block lists');
    }

    protected function fire(): int
    {
        $this->info('Downloading StopForumSpam block lists...');

        if ($this->stopForumSpamService->downloadAndProcessLists()) {
            $this->info('Block lists successfully updated and compiled!');
            return Command::SUCCESS;
        }

        $this->error('Failed to update some or all block lists.');
        return Command::FAILURE;
    }
}
