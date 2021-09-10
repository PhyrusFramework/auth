<?php

class Auth {

    const ERROR_MISSING = 'token missing';
    const ERROR_EXPIRED = 'token expired';
    const ERROR_DB = 'token not in DB';
    const ERROR_PAYLOAD = 'token wrong payload';
    const ERROR_USER = 'user not found';
    const ERROR_PASSWORD = 'incorrect password';

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
     * Generate an error response.
     * 
     * @param string message
     * 
     * @return Generic response
     */
    private static function error(string $msg) : Generic {
        return new Generic([
            'error' => $msg
        ]);
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
    public static function login(string $username, string $password, ?array $cookies = null) : Generic {

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

        if ($user == null) return self::error(self::ERROR_USER);

        if (!$user->checkPassword($password)) {
            return self::error(self::ERROR_PASSWORD);
        }

        self::$user = $user;

        // Login correct, now create tokens

        if (Config::get('auth.tokens.storeDB')) {
            $maxTokens = Config::get('auth.tokens.perUser');
            if ($maxTokens > 0) {
                $tokens = UserToken::find('active = 1 AND user_id = :ID ORDER BY createdAt ASC', ['ID' => $user->ID]);
    
                if (sizeof($tokens) >= $maxTokens) {
                    $tokens[0]->delete();
                }
            }
        }

        $token = UserToken::generate($user->ID);
        $refresh = UserToken::generate($user->ID, 'refresh');

        if (Config::get('auth.tokens.storeDB')) {
            $token->save();
            $refresh->save();
        }

        if (is_array($cookies)) {
            if (isset($cookies['token'])) {
                Cookie::set($cookies['token'], $token->value, Config::get('auth.tokens.duration') / 3600);
            }
            if (isset($cookies['refresh'])) {
                Cookie::set($cookies['refresh'], $refresh->value, Config::get('auth.tokens.refreshDuration') / 3600);
            }
        }

        return new Generic([
            'success' => true,
            'token' => $token->value,
            'refresh' => $refresh->value
        ]);

    }

    /**
     * Register a new user
     * 
     * @param string ['email', 'password', ?'username']
     * 
     * @return AuthUser|false
     */
    public static function register(array $data) {

        if (!isset($data['email']) || !isset($data['password'])) {
            return false;
        }

        $useUsername = Config::get('auth.username');

        if ($useUsername && !isset($data['username'])) {
            return false;
        }

        $class = Config::get('auth.class');

        $user = $class::findOne('email = :email', [
            'email' => $data['email']
        ]);

        if ($user != null) {
            return false;
        }

        $user = new $class();
        $user->email = $data['email'];
        $user->setPassword($data['password']);
        if ($useUsername) {
            $user->username = $data['username'];
        }

        $user->save();

        self::$user = $user;
        return $user;

    }

    /**
     * Validate token
     * 
     * @param string token
     * @param string type 'session'|'refresh'
     * 
     * @return Generic error or success
     */
    private static function validateToken(string $token, string $type = 'session') : Generic {

        if (Config::get('auth.tokens.storeDB')) {

            $old = UserToken::find('createdAt < NOW() - INTERVAL '. Config::get('auth.tokens.durationRefresh') .' SECOND');
            foreach($old as $oldTk) {
                $oldTk->delete();
            }

            $tk = UserToken::findOne('type = :type AND value = :value', [
                'type' => $type,
                'value' => $token
            ]);
    
            if ($tk == null) {
                return self::error(self::ERROR_DB);
            }
    
            if (!$tk->active) {
                return self::error(self::ERROR_EXPIRED);
            }
        } else {
            $tk = new UserToken();
            $tk->value = $token;
        }

        $key = Config::get('auth.tokens.key');
        $jwt = new JWT($key);

        if ($jwt->isExpired($token)) {

            $tk->active = false;
            if (Config::get('auth.tokens.storeDB')) {
                $tk->save();
            }

            return self::error(self::ERROR_EXPIRED);
        }

        $content = $jwt->decode($token);

        if (!isset($content->userId)) {
            return self::error(self::ERROR_PAYLOAD);
        }

        $class = Config::get('auth.class');
        $user = $class::findOne('ID = :ID', ['ID' => intval($content->userId) ]);

        if ($user == null) {
            return self::error(self::ERROR_USER);
        }

        self::$user = $user;

        return new Generic([
            'success' => true,
            'token' => $tk,
            'user' => $user
        ]);
    }

    /**
     * Validate token. If not passed, it is obtained from authorization header.
     * 
     * @param string token
     * 
     * @return Generic error or success
     */
    public static function validate(?string $token = null) : Generic {

        $header = $token == null ? AUTHORIZATION() : $token;
        if (empty($header)) {
            return self::error(self::ERROR_MISSING);
        }

        return self::validateToken($header);

    }

    /**
     * Validate token and try to refresh it if it's expired.
     * 
     * @param string token
     * @param string refreshToken
     * @param array [Optional] cookies to store new tokens.
     * 
     * @return Generic error or success
     */
    public static function validateAndRefresh(string $token, ?string $refresh = null, ?array $cookies = null) : Generic {

        $result = self::validate($token);
        if (!$result->has('error')) {
            return $result;
        }

        if ($result->error != self::ERROR_EXPIRED) {
            return $result;
        }

        return self::refresh($refresh, $cookies);

    }

    /**
     * Validate tokens directly from cookies.
     * 
     * @param array cookies names.
     * 
     * @return Generic error or success
     */
    public static function validateFromCookies(array $cookies) : Generic {

        if (!isset($cookies['token'])) {
            return self::error(self::ERROR_MISSING);
        }

        $token = Cookie::get($cookies['token']);
        if (empty($token)) {
            return self::error(self::ERROR_MISSING);
        }

        $refresh = null;
        if (isset($cookies['refresh'])) {
            $refresh = Cookie::get($cookies['refresh']);
        }

        return self::validateAndRefresh($token, $refresh, $cookies);

    }

    /**
     * Generate a new token using the refresh token.
     * 
     * @param string refreshToken
     * @param array [Optional] cookies to store the new tokens.
     * 
     * @return Generic error or success
     */
    public static function refresh(string $refreshToken, ?array $cookies = null) : Generic {

        $result = self::validateToken($refreshToken, 'refresh');

        if ($result->has('error')) {
            return $result;
        }

        $user = $result->user;

        // Disable this refresh token, so it gets replaced.
        $result->token->active = false;
        if (Config::get('auth.tokens.storeDB')) {
            $result->token->save();
        }

        $token = UserToken::generate($user->ID);
        $refresh = UserToken::generate($user->ID, 'refresh');

        if (Config::get('auth.tokens.storeDB')) {
            $token->save();
            $refresh->save();
        }

        if (is_array($cookies)) {
            if (isset($cookies['token'])) {
                Cookie::set($cookies['token'], $token->value, Config::get('auth.tokens.duration') / 3600);
            }
            if (isset($cookies['refresh'])) {
                Cookie::set($cookies['refresh'], $token->value, Config::get('auth.tokens.refreshDuration') / 3600);
            }
        }

        return new Generic([
            'success' => true,
            'token' => $token->value,
            'refresh' => $refresh->value
        ]);

    }



}