<?php
// Copy to config.php and fill in private production values.
// Do not commit config.php.
return [
    'host' => '127.0.0.1',
    'port' => '3306',
    'name' => 'teamdev_proxy',
    'user' => 'MYSQL_USERNAME',
    'pass' => 'MYSQL_PASSWORD',
    'site' => 'HCAPTCHA_SITE_KEY',
    'secret' => 'HCAPTCHA_SECRET_KEY',
    'admin' => 'REPLACE_WITH_A_LONG_RANDOM_ADMIN_PASSWORD',
    'base' => 'https://your-domain.example',
];
