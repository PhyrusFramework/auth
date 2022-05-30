<?php

$_endpoint_login = Config::get('auth.endpoints.login');
$_endpoint_signup = Config::get('auth.endpoints.signup');
$_endpoint_validate = Config::get('auth.endpoints.validate');
$_endpoint_refresh = Config::get('auth.endpoints.refresh');
$_endpoint_user = Config::get('auth.endpoints.user');
$_endpoint_logout = Config::get('auth.endpoints.logout');

if ($_endpoint_login != null) {
    
    Router::add($_endpoint_login, [
        
    'POST' => function($req) {
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
                'token' => $tokens->sessionToken,
                'refreshToken' => $tokens->refreshToken,
                'user' => $tokens->user->ID
            ]);
        })
        ->catch(function($err) {
            response_die('unauthorized');
        });

    }]);
}

if ($_endpoint_signup != null) {

    Router::add($_endpoint_signup, [
        
    'POST' => function($req) {
        $req->require('email', 'password');

        $data = [
            'email' => $req->email,
            'password' => $req->password
        ];

        if (Config::get('auth.username')) {
            $req->require('username');
            $data['username'] = $req->username;
        }

        Auth::register($data)
        ->then(function($user) use ($req, $data) {

            if ($req->has('login') && $req->login) {

                $loginWith = Config::get('auth.loginWith');

                $username = strpos($loginWith, 'email') !== FALSE ?
                    $data['email'] : $data['username'];

                Auth::login($username, $data['password'])
                ->then(function($tokens) {
                    response_die('ok', [
                        'token' => $tokens->sessionToken,
                        'refreshToken' => $tokens->refreshToken,
                        'user' => $tokens->user->ID
                    ]);
                })
                ->catch(function($err) {
                    response_die('unauthorized');
                });

            } else {
                response_die('ok', [
                    'user' => $user->ID
                ]);
            }

        })
        ->catch(function($error) {
            response_die('bad', [
                'message' => $error
            ]);
        });
    }]);

}

if ($_endpoint_validate != null) {

    Router::add($_endpoint_validate, [

        'POST' => function($req) {

            $tk = $req->headers->Auth();
            if (!$tk) {
                response_die('unauthorized');
            }

            Auth::validate($tk)
            ->then(function($tokens) {
                response_die('ok', [
                    'token' => $tokens->sessionToken,
                    'refreshToken' => $tokens->refreshToken,
                    'user' => $tokens->user->ID
                ]);
            })
            ->catch(function() {
                response_die('unauthorized');
            });

        }

    ]);

}

if ($_endpoint_refresh != null) {

    Router::add($_endpoint_refresh, [

        'POST' => function($req) {
            $req->require('refreshToken');
    
            $tk = $req->headers->Auth();
            if (!$tk) {
                response_die('bad', [
                    'error' => 'missing authorization token'
                ]);
            }
    
            Auth::validate($tk, $req->refreshToken)
            ->then(function($tokens) {
                response_die('ok', [
                    'token' => $tokens->sessionToken,
                    'refreshToken' => $tokens->refreshToken,
                    'user' => $tokens->user->ID
                ]);
            })
            ->catch(function() {
                response_die('unauthorized');
            });
    
        }
    
    ]);

}

if ($_endpoint_user != null) {

    Router::add($_endpoint_user, [

        'GET' => function($req) {
    
            $tk = $req->headers->Auth();
            if (!$tk) {
                response_die('unauthorized');
            }
    
            Auth::validate($tk)
            ->then(function($tokens) {

                $u = Auth::getUser();

                $response = [
                    'ID' => $u->ID,
                    'email' => $u->email,
                ];

                if (Config::get('auth.username')) {
                    $response['username'] = $u->username;
                }

                $meta = Config::get('auth.endpoints.userData');
                if ($meta != null && is_array($meta)) {
                    foreach($meta as $m) {

                        $n = $m;

                        /**
                         * xxx
                         * meta/xxx
                         * translation/xxx
                         * resource/xxx
                         * resources/xxx
                         */
                        $type = 'meta';
                        if (strpos($m, '/') !== false) {
                            $parts = explode('/', $m);
                            $type = $parts[0];
                            $n = $parts[1];
                        }

                        if ($type == 'translation') {
                            $response[$n] = $u->getTranslation(
                                $n,
                                Translate::getLanguage()
                            );
                        } else if ($type == 'resource') {
                            $resources = $u->getResources($n);
                            $response[$n] = sizeof($resources) > 0 ?
                                $resources[0]->file : null;
                        } else if ($type == 'resources') {
                            $resources = $u->getResources($n);
                            $list = [];

                            foreach($resources as $r) {
                                $list[] = $r->file;
                            }
                            $response[$n] = $list;
                        } else {
                            $response[$m] = $u->getMeta($m);
                        }

                    }
                }

                response_die('ok', $response);
            })
            ->catch(function() {
                response_die('unauthorized');
            });
    
        }
    
    ]);

}


if ($_endpoint_logout != null) {

    Router::add($_endpoint_logout, [

    'POST' => function($req) {

        // Get authorization token
        $tk = $req->headers->Auth();
        if (!$tk) {
            response_die('bad');
        }

        if (Config::get('auth.tokens.storeDB')) {

            // Find that token in Database
            $res = DB::run('SELECT * FROM user_tokens WHERE value = :tk', [
                'tk' => $tk
            ]);

            // If found
            if ($res->something) {

                // Save User ID
                $user = $res->first->user_id;

                // Disable this token
                DB::run('UPDATE user_tokens SET active = 0 WHERE value = :tk', [
                    'tk' => $tk
                ]);
    
                // Try to find the refresh token
                $res = DB::run("SELECT * FROM user_tokens WHERE active = 1 AND type = 'refreshToken' AND user_id = :uid", [
                    'uid' => intval($user)
                ]);
    
                // If only one refresh token active, that's it
                if ($res->count == 1) {
                    DB::run("UPDATE user_tokens SET active = 0 WHERE ID = :ID", [
                        'ID' => intval($res->first->ID)
                    ]);
                }
    

            }
        }

        // Remove cookies if were used
        Auth::deleteCookies();

        response_die('ok');

    }

    ]);

}