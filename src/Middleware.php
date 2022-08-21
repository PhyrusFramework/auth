<?php

Router::addMiddleware('authenticated', function($req, $params) {

    $tk = $req->headers->Auth();

    if (!$tk) {
        $cookies = Auth::getCookies();
        $tk = $cookies->sessionToken;
    }

    if (empty($tk) || $tk == 'null') {
        response_die('unauthorized');
    }

    return Auth::validate($tk)
    ->isSuccess() ? true : false;

});