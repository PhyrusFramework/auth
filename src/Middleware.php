<?php

Router::addMiddleware('authenticated', function($req, $params) {

    return new Promise(function($resolve, $reject) use ($req, $params) {

        $tk = $req->headers->Auth();

        if (!$tk) {
            $cookies = Auth::getCookies();
            $tk = $cookies->sessionToken;
        }

        if (empty($tk) || $tk == 'null') {
            response_die('unauthorized');
        }

        Auth::validate($tk)
        ->then(function() use ($resolve) {
            $resolve();
        })
        ->catch(function() {
            response_die('unauthorized');
        });

    });

});