<?php

Ajax::add('Auth.Login', function($req) {
    $req->requireMethod('POST');
    $req->require('password');

    if ($req->has('username')) {
        $username = $req->username;
    } else if ($req->has('email')) {
        $username = $req->email;
    } else {
        response_die('bad');
    }

    $result = Auth::login($req->username, $req->password);

    if (!$result) {
        response_die('unauthorized');
    }

    response_die('ok', [
        'token' => $result->token,
        'refreshToken' => $result->refreshToken
    ]);

});

Ajax::add('Auth.Register', function($req) {
    $req->requireMethod('POST');
    $req->require('email', 'password');

    $data = [
        'email' => $req->email,
        'password' => $req->password
    ];

    if (Config::get('auth.use.username')) {
        $req->require('username');
        $data['username'] = $req->username;
    }

    $user = Auth::register($data);

    response_die('ok', [
        'user' => $user->ID
    ]);
});