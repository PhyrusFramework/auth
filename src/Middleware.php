<?php

Router::addMiddleware('authenticated', function($req, $params) {

    $tk = $req->headers->Auth();

    if (!$tk) {
        $cookies = Auth::getCookies();
        $tk = $cookies->token;
    }

    if (empty($tk) || $tk == 'null') {
        response_die('unauthorized', [
            'code' => 'token.missing'
        ]);
    }

    $valid = Auth::validate($tk);

    if ($valid->isSuccess()) {
        return true;
    }

    return response_die('unauthorized', [
        'code' => 'token.invalid'
    ]);


});