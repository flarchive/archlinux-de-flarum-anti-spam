<?php

namespace ArchLinux\AntiSpam\Console;

use ArchLinux\AntiSpam\Service\StopForumSpamService;
use Carbon\Carbon;
use Flarum\Console\AbstractCommand;
use Flarum\Http\SlugManager;
use Flarum\Http\UrlGenerator;
use Flarum\Post\Post;
use Flarum\Post\PostRepository;
use Flarum\User\User;
use Flarum\User\UserRepository;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\String\UnicodeString;

class CheckAgainstStopForumSpamBlockLists extends AbstractCommand
{
    public function __construct(
        private readonly StopForumSpamService $stopForumSpamService,
        private readonly UserRepository $userRepository,
        private readonly UrlGenerator $urlGenerator,
        private readonly SlugManager $slugManager,
        private readonly PostRepository $postRepository,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('anti-spam:check-against-block-lists')->setDescription(
            'Check against StopForumSpam block lists'
        );
    }

    protected function fire(): int
    {
        /** @var User $user */
        foreach ($this->userRepository->query()->get() as $user) {
            if ($this->isListed($user)) {
                $this->output->writeln($this->createUserLink($user));
            }
        }

        /** @var Post $post */
        foreach (
            $this->postRepository->query()->where('created_at', '>=', Carbon::now()->subYears(1))->get() as $post
        ) {
            if (!$post->ip_address || !$post->user) {
                continue;
            }

            if ($this->stopForumSpamService->isSpamIp($post->ip_address)) {
                $this->output->writeln($this->createUserLink($post->user));
            }
        }

        return Command::SUCCESS;
    }

    private function isListed(User $user): bool
    {
        if ($this->stopForumSpamService->isSpamUsername($user->username)) {
            return true;
        }

        $emailDomain = (new UnicodeString($user->email))->afterLast('@')->toString();
        if ($this->stopForumSpamService->isSpamDomain($emailDomain)) {
            return true;
        }

        return false;
    }

    private function createUserLink(User $user): string
    {
        return $this->urlGenerator->to('forum')->route(
            'user',
            ['username' => $this->slugManager->forResource(User::class)->toSlug($user)]
        );
    }
}
