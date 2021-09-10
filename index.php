<?php
require_once(__DIR__ . '/src/User.php');
require_once(__DIR__ . '/src/Auth.php');
require_once(__DIR__ . '/src/Token.php');
require_once(__DIR__ . '/src/ajax.php');

if (Config::get('development_mode')) {

    if (Config::get('auth') == null) {
        Config::save('auth', [
            'username' => true,
            'loginWith' => 'email|username',
            'tokens' => [
                'key' => 'Auth',
                'duration' => 3600,
                'durationRefresh' => 604800,
                'perUser' => 3,
                'storeDB' => true
            ],
            'class' => 'AuthUser'
        ]);
    }

}