<?php

class UserToken extends ORM {

    public function Definition() {

        return [
            'name' => 'user_tokens',
            'columns' => [
                [
                    'name' => 'user_id',
                    'type' => 'BIGINT',
                    'notnull' => true
                ],
                [
                    'name' => 'type',
                    'type' => 'VARCHAR(100)',
                    'notnull' => true,
                    'default' => 'session'
                ],
                [
                    'name' => 'value',
                    'type' => 'TEXT',
                    'notnull' => true
                ],
                [
                    'name' => 'active',
                    'type' => 'TINYINT',
                    'notnull' => true,
                    'default' => 1
                ]
            ]
        ];

    }

    public static function generate($userId, $type = 'session') {

        $token = null;

        if (Config::get('auth.tokens.storeDB')) {
            $token = UserToken::findOne('active = 0 AND user_id = :user AND type = :type', [
                'user' => $userId,
                'type' => $type
            ]);
        }

        if ($token == null) {
            $token = new UserToken();
        }

        $token->user_id = $userId;
        $token->type = $type;

        $key = Config::get('auth.tokens.key', 'Auth');
        $age = Config::get('auth.tokens.' . ($type == 'session' ? 'duration' : 'refreshDuration'), 
                $type == 'session' ? 3600 : 604800);

        $jwt = new JWT($key, $age);

        $token->value = $jwt->encode(['userId' => $userId]);
        $token->active = true;
        $token->createdAt = datenow();
        return $token;
    }

}