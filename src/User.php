<?php

class AuthUser extends AdvancedORM {

    public function Definition(DBBuilder $table) {

        $table->name('users');

        $username = Config::get('auth.username');
        if ($username) {
            $table->column('username')
                ->unique()
                ->notnull();
        }

        $table->column('email')
            ->unique()
            ->notnull();

        $table->column('password', 'TEXT')
            ->notSerializable();
    }

    public function reference_column() {
        return 'user_id';
    }

    /**
     * Set user password and save it to the database.
     * 
     * @param string $password
     * 
     * @return string encoded password
     */
    public function setPassword(string $password) : string {
        $pass = generate_password($password);
        $this->password = $pass;
        return $pass;
    }

    /**
     * Validate user password
     * 
     * @param string $password
     * 
     * @return bool
     */
    public function checkPassword(string $password) : bool {
        return password_verify($password, $this->password);
    }

    /**
     * Generate new token for this user
     * 
     * @param array $params
     * 
     * @return string
     */
    public function generateToken($params = []) : string {

        $token = UserToken::generate($this, $params);
        return $token->value;

    }

    /**
     * Get existing token for this user.
     * 
     * @param string $type
     * 
     * @return ?string
     */
    public function getToken(string $type) : ?string {

        $tk = UserToken::find('active = 1 AND user_id = :ID AND type = :type ORDER BY createdAt DESC', [
            'ID' => $this->ID,
            'type' => $type
        ]);

        return $tk == null ? null : $tk->value;

    }

    /**
     * Generate new authentication tokens for this user.
     * 
     * @return Generic
     */
    public function authTokens() : Generic {
        $session = $this->generateToken([
            'type' => 'sessionToken',
            'duration' => Config::get('auth.tokens.sessionDuration')
        ]);

        $refresh = $this->generateToken([
            'type' => 'refreshToken',
            'duration' => Config::get('auth.tokens.refreshDuration'),
            'payload' => [
                'sessionToken' => $session
            ]
        ]);

        return new Generic([
            'sessionToken' => $session,
            'refreshToken' => $refresh,
            'user' => $this
        ]);
    }

    /**
     * Refresh user's sessionToken
     * 
     * @param string $refreshToken
     * @param ?string $expiredToken
     * 
     * @return Promise
     */
    public function refreshToken(string $refreshToken, ?string $expiredToken) : Promise {

        $user = $this;

        return new Promise(function($resolve, $reject) use($refreshToken, $expiredToken, $user) {

            $tk = UserToken::instance($refreshToken, 'refreshToken');

            $tk->validate()
            ->then(function() use ($tk, $user, $expiredToken, $resolve, $reject) {

                $payload = $tk->getPayload();

                if (!isset($payload->userId)) {
                    $reject('Unknown token user');
                    return;
                }

                if (intval($payload->userId) != $user->ID) {
                    $reject('User ID mismatch');
                    return;
                }

                if ($expiredToken != null && isset($payload->sessionToken)) {
                    if ($expiredToken != $payload->sessionToken) {
                        $reject('sessionToken mismatch');
                        return;
                    }
                }

                if (Config::get('auth.tokens.storeDB') && $tk->ID > 0) {
                    $tk->disable();
                }

                $newTokens = $user->authTokens();

                $resolve($newTokens);

            })
            ->catch(function($err) {
                $reject($err);
                return;
            });

            
        });

        
    }

}