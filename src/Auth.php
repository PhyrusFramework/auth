<?php

class Auth {

    /**
     * @var AuthUser $user
     */
    private static $user;

    /**
     * Get logged user.
     * 
     * @return AuthUser
     */
    public static function getUser() : ?AuthUser{
        return self::$user;
    }

    /**
     * Set current logged User
     * 
     * @param ?AuthUser $user
     */
    public static function setUser(?AuthUser $user) {
        self::$user = $user;
    }

    /**
     * Create database tables if don't exist.
     */
    public static function CreateTables() {
        AuthUser::CreateTable();
        if (Config::get('auth.tokens.storeDB')) {
            UserToken::CreateTable();
        }
    }

    /**
     * Sign in using user credentials.
     * 
     * @param string username Email or username
     * @param string password
     * @param array cookies to store the tokens ['token', 'refresh'] 
     * 
     * @return Generic error or success response
     */
    public static function login(string $username, string $password) : Promise {

        return new Promise(function($resolve, $reject) use ($username, $password) {

            $useUsername = Config::get('auth.username');
            if (!$useUsername) {
                $method = 'email';
            } else {
                $method = Config::get('auth.loginWith', 'email|username');
            }

            $q = '';
            if (Text::instance($method)->contains('email')) {
                $q .= 'email = :username';
            }
            if (Text::instance($method)->contains('username')) {
                if (!empty($q)) {
                    $q .= ' OR ';
                }

                $q .= 'username = :username';
            }

            $class = Config::get('auth.class');
            $user = $class::findOne($q, [
                'username' => $username
            ]);

            if ($user == null) {
                $reject('user does not exist');
                return;
            }

            if (!$user->checkPassword($password)) {
                $reject('invalid password');
                return;
            }

            self::$user = $user;

            // Login correct, now create tokens
            $tokens = $user->authTokens();
            $resolve($tokens);

        });

    }

    /**
     * Register a new user
     * 
     * @param string ['email', 'password', ?'username']
     * 
     * @return AuthUser|false
     */
    public static function register(array $data) : Promise {

        return new Promise(function($resolve, $reject) use($data) {

            if (!isset($data['email']) || !isset($data['password'])) {
                $reject('email or password missing');
                return;
            }
    
            $useUsername = Config::get('auth.username');
    
            if ($useUsername && !isset($data['username'])) {
                $reject('username missing');
                return;
            }
    
            $class = Config::get('auth.class');
    
            $user = $class::findOne('email = :email', [
                'email' => $data['email']
            ]);
    
            if ($user != null) {
                $reject('email already exists');
                return;
            }
    
            $user = new $class();
            $user->email = $data['email'];
            $user->setPassword($data['password']);
            if ($useUsername) {
                $user->username = $data['username'];
            }
            $user->createdAt = datenow();
    
            $user->save();
            $resolve($user);

        });

    }

    /**
     * Validate tokens to get logged user and refresh his tokens if necessary.
     * 
     * @param ?string $sessionToken
     * @param ?string $refreshToken
     * 
     * @return Generic
     */
    public static function validate(?string $sessionToken, ?string $refreshToken = null) {

        return new Promise(function($resolve, $reject) use ($sessionToken, $refreshToken) {

            if (empty($sessionToken)) {
                $reject('token empty');
                return;
            }

            $tk = UserToken::instance($sessionToken, 'sessionToken');

            if ($tk == null) {
                $reject('token not found');
                return;
            }

            $tk->validate()
            ->then(function() use ($tk, $sessionToken, $refreshToken, $resolve) {
                $user = $tk->getUser();
                Auth::setUser($user);

                $resolve(new Generic([
                    'sessionToken' => $sessionToken,
                    'refreshToken' => $refreshToken,
                    'user' => $user
                ]));
            })
            ->catch( function($err) use ($tk, $refreshToken, $resolve, $reject) {
                
                if (empty($refreshToken)) {
                    $reject($err);
                    return;
                }

                $rtk = UserToken::instance($refreshToken, 'refreshToken');

                $rtk->validate()
                ->then(function() use($rtk, $tk, $resolve, $reject) {
                    $user = $rtk->getUser();

                    if ($user == null) {
                        $reject('user not found');
                        return;
                    }

                    Auth::setUser($user);

                    $user->refreshToken($rtk->value, $tk->value)
                    ->then( function( $newTokens ) use ($resolve) {
                        $resolve($newTokens);
                    })
                    ->catch(function($err) use ($reject) {
                        $reject($err);
                    });

                })
                ->catch(function($err) use ($reject) {
                    $reject($err);
                });

            });


        });

    }

    /**
     * Set tokens as cookies 'sessionToken' and 'refreshToken'.
     * 
     * @param string $token
     * @param string [Optional] $refreshToken
     */
    public static function setCookies(string $token, string $refreshToken = '') {

        Cookie::set('sessionToken', $token, Config::get('auth.tokens.sessionDuration', 3600));
        if (!empty($refreshToken)) {
            Cookie::set('refreshToken', $refreshToken, Config::get('auth.tokens.refreshDuration'), 604800);
        }

    }

    /**
     * Get tokens from cookies.
     * 
     * @return Generic
     */
    public static function getCookies() {
        $token = Cookie::get('sessionToken');
        $refresh = Cookie::get('refreshToken');

        return new Generic([
            'sessionToken' => $token,
            'refreshToken' => $refresh
        ]);
    }

    /**
     * Delete Auth token cookies.
     */
    public static function deleteCookies() {
        Cookie::destroy('sessionToken');
        Cookie::destroy('refreshToken');
    }

}