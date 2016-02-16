<?php
return [
    'issuer' => env('JWT_ISSUER', false),
    'secret' => env('JWT_SECRET'),
    'expOffset' => env('JWT_TTL', 3600),
    'requiredClaims' => ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti']
];
