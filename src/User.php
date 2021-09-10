<?php

class AuthUser extends AdvancedORM {

    public function Definition() {

        $columns = [];

        $username = Config::get('auth.username');
        if ($username) {
            $columns[] = [
                'name' => 'username',
                'type' => 'VARCHAR(200)',
                'unique' => true,
                'notnull' => true
            ];
        }

        $columns[] = [
            'name' => 'email',
            'type' => 'VARCHAR(200)',
            'unique' => true,
            'notnull' => true
        ];
        
        $columns[] = [
            'name' => 'password',
            'type' => 'TEXT'
        ];


        return [
            'name' => 'users',
            'columns' => $columns
        ];
    }

    public function reference_column() {
        return 'user_id';
    }

    public function setPassword(string $password) : string {
        $pass = generate_password($password);
        $this->password = $pass;
        return $pass;
    }

    public function checkPassword(string $password) : bool {
        return password_verify($password, $this->password);
    }

}