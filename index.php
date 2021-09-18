<?php
require_once(__DIR__ . '/src/User.php');
require_once(__DIR__ . '/src/Auth.php');
require_once(__DIR__ . '/src/Token.php');
require_once(__DIR__ . '/src/ajax.php');

if (Config::get('development_mode')) {

    if (Config::get('auth') == null) {
        Config::save('auth', [
            'class' => 'AuthUser',
            'username' => true,
            'loginWith' => 'email|username',
            'tokens' => [
                'storeDB' => true,
                'key' => 'Auth',
                'sessionDuration' => 3600,
                'refreshDuration' => 604800,
                'perUser' => 100
            ]
        ]);
    }

}