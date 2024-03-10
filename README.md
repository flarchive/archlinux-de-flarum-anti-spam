## Anti-Spam - Spam protection for forum.archlinux.de

This [Flarum](https://flarum.org/) extension is specific to [forum.archlinux.de](https://forum.archlinux.de/). You might
find its code useful to implement your own solution.

### Installation

```sh
composer require archlinux-de/flarum-anti-spam
```

### Optional configuration:

The extension can be configured by adding the following keys to ``config.php``:

```php
<?php return [
    // ...
    'anti_spam' => [
        'user_agent_allowed' => ['BSD'],
        'user_agent_blocked' => ['DOS', 'Windows'],
        'geoip_database' => '/opt/GeoLite2-Country.mmdb',
        'country_allowed' => ['FR', 'NL'],
        'country_blocked' => ['DE'],
        'ip_allowed' => ['10.0.0.0/8', '::1'],
        'ip_blocked' => ['192.168.0.0/16'],
        'email_domain_allowed' => ['archlinux.de'],
        'email_domain_blocked' => ['example.com'],
    ],
];
```
