<?php
require_once(__DIR__ . '/src/User.php');
require_once(__DIR__ . '/src/Auth.php');
require_once(__DIR__ . '/src/Token.php');

if (Config::get('project.development_mode')) {

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
            ],
            'endpoints' => [
                'login' => '/api/auth/login',
                'signup' => '/api/auth/signup',
                'validate' => '/api/auth/validate',
                'refresh' => '/api/auth/refresh',
                'logout' => '/api/auth/logout',
                'user' => '/api/auth/user',
                'userData' => []
            ]
        ]);

        Auth::CreateTables();
    }

}

require_once(__DIR__ . '/src/Endpoints.php');
require_once(__DIR__ . '/src/Middleware.php');