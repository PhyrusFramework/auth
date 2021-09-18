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

    Auth::login($username, $req->password)
    ->then(function($tokens) {
        response_die('ok', [
            'token' => $result->sessionToken,
            'refreshToken' => $result->refreshToken,
            'user' => $result->user->ID
        ]);
    })
    ->catch(function($err) {
        response_die('unauthorized');
    });

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

    Auth::register($data)
    ->then(function($user) {
        response_die('ok', [
            'user' => $user->ID
        ]);
    })
    ->catch(function() {
        response_die('bad');
    });
});