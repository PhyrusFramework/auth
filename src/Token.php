<?php

class UserToken extends ORM {

    public function Definition() {

        return [
            'name' => 'user_tokens',
            'columns' => [
                [
                    'name' => 'user_id',
                    'type' => 'BIGINT',
                    'notnull' => true,
                    'default' => 0
                ],
                [
                    'name' => 'type',
                    'type' => 'VARCHAR(100)',
                    'notnull' => true,
                    'default' => 'token'
                ],
                [
                    'name' => 'active',
                    'type' => 'TINYINT',
                    'notnull' => true,
                    'default' => 1
                ],
                [
                    'name' => 'value',
                    'type' => 'TEXT',
                    'notnull' => true
                ]
            ]
        ];

    }

    /**
     * Generate JWT object to encode and decode user tokens.
     * 
     * @param int $age
     * 
     * @return JWT
     */
    private static function jwt($age = 3600) : JWT {
        return new JWT(Config::get('auth.tokens.key'), $age);
    }

    /**
     * Find token in the database
     * 
     * @param string $token
     * @param ?string $type
     * 
     * @return ?UserToken
     */
    public static function findToken(string $token, ?string $type) : ?UserToken {
        $condition = 'active = 1 AND value = :value';
        $params = ['value' => $token];
        if (!empty($type)) {
            $condition .= ' AND type = :type';
            $params['type'] = $type;
        }

        return UserToken::findOne($condition, $params);
    }

    /**
     * Creates a UserToken object for a token
     * 
     * @param string $token
     * @param ?string $type
     * 
     * @return UserToken
     */
    public static function instance(string $token, $type = null) : UserToken {
        $tk = new UserToken();
        $tk->value = $token;

        if (!empty($type)) {
            $tk->type = $type;
        } else {
            $tk->type = '';
        }

        $found = self::findToken($tk->value, $tk->type);
        if ($found != null) {
            $tk = $found;
        }

        $payload = self::jwt()->decode($token);

        if (!$payload) {
            return $tk;
        }

        if (!isset($payload->userId)) {
            return $tk;
        }

        $tk->user_id = intval($payload->userId);

        return $tk;
    }

    /**
     * Generate a new token for a user.
     * 
     * @param AuthUser $user
     * @param array $tokenData
     * 
     * @return UserToken
     */
    public static function generate(AuthUser $user, array $tokenData = []) : UserToken {

        $params = Arr::instance($tokenData)->force([
            'type' => 'token',
            'duration' => 3600,
            'payload' => []
        ])->getArray();

        $payload = $params['payload'];

        $payload['userId'] = $user->ID;

        $token = new UserToken();
        $token->user_id = $user->ID;
        $token->type = $params['type'];

        $key = Config::get('auth.tokens.key', 'Auth');
        $age = $params['duration'];

        $token->value = self::jwt($age)->encode($payload);
        $token->createdAt = datenow();

        if (Config::get('auth.tokens.storeDB')) {

            // Check if there is a token to replace
            $inactive = self::findOne('user_id = :ID AND type = :type AND active = 0 ORDER BY createdAt ASC', [
                'ID' => $user->ID,
                'type' => $params['type']
            ]);
            if ($inactive != null) {
                $inactive->value = $token->value;
                $inactive->createdAt = datenow();
                $inactive->active = 1;
                $token = $inactive;
            }
            /////

            $token->save();

            $tokens = self::find('active = 1 AND user_id = :ID AND type = :type ORDER BY createdAt ASC', [
                'ID' => $user->ID,
                'type' => $params['type']
            ]);

            $perUser = Config::get('auth.tokens.perUser');

            if ($perUser > 0 && sizeof($tokens) > $perUser) {
                for($i = 0; $i < sizeof($tokens) - $perUser; ++$i) {
                    $tokens[$i]->disable();
                }
            }
        }

        return $token;
    }

    /**
     * Disable token so it can be replaced with another new token.
     */
    public function disable() {
        $this->active = 0;
        $this->save('active');
    }

    /**
     * Get User from token
     * 
     * @return ?AuthUser
     */
    public function getUser() : ?AuthUser {

        if (!$this->user_id) return null;

        $cl = Config::get('auth.class');
        return $cl::findOne('ID = :ID', [
            'ID' => $this->user_id
        ]);

    }

    /**
     * Is the token expired?
     * 
     * @return bool
     */
    public function isExpired() : bool {
        $payload = self::jwt()->decode($this->value);

        return $payload === false;
    }

    /**
     * Get token payload
     * 
     * @return object
     */
    public function getPayload() {
        $payload = self::jwt()->decode($this->value);

        return $payload === false ? [] : $payload;
    }

    /**
     * Validate token. Optionally you can specify the user to improve accuracy.
     * 
     * @param ?AuthUser $forUser
     * 
     * @return Promise
     */
    public function validate(?AuthUser $forUser = null) : Promise {

        $token = $this;

        return new Promise(function($resolve, $reject) use($forUser, $token) {

            if (Config::get('auth.tokens.storeDB')) {

                $tk = self::findToken($token->value, $token->type);
        
                if ($tk == null) {
                    $reject('token not found in database');
                    return;
                }

            } else {
                $tk = $token;
            }

            if ($tk->isExpired()) {

                if ($tk->ID > 0 && Config::get('auth.tokens.storeDB')) {
                    $tk->disable();
                }
            
                $reject('token expired');
                return;
            }

            $content = self::jwt()->decode($tk->value);

            if (!isset($content->userId)) {
                $reject('token missing user ID');
                return;
            }

            $class = Config::get('auth.class');
            $user = $class::findOne('ID = :ID', ['ID' => intval($content->userId) ]);

            if ($user == null) {
                $reject('token user does not exist');
                return;
            }

            if (Config::get('auth.tokens.storeDB')) {
                if ($user->ID != $tk->user_id) {
                    $reject('token user mismatch');
                    return;
                }
            }

            if ($forUser != null) {
                if ($forUser->ID != $user->ID) {
                    $reject('token user mismatch');
                    return;
                }
            }

            $resolve();

        });

    }

}