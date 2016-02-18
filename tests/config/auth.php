<?php

return [
    'defaults' => [
        'guard' => 'jwt',
    ],
    'guards' => [
        'jwt' => [
            'driver' => 'jwt',
            'provider' => 'users',
        ],
        'jwt-alt' => [
            'driver' => 'jwt',
            'provider' => 'users',
        ]
    ],
    'providers' => [
        'users' => [
            'driver' => 'eloquent',
            'model' => CanisUnit\Lumen\Jwt\User::class
        ]
    ]
];
