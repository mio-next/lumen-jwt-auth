<?php
return [
    'adapter' => env('JWT_ADAPTER', 'lcobucci'),
    'issuer' => env('JWT_ISSUER', false),
    'secret' => env('JWT_SECRET'),
    'expOffset' => env('JWT_TTL', 3600),
    'jtiInHeader' => env('JWT_JTI_HEADER', false),
    'requiredClaims' => ['iat', 'iss', 'exp', 'nbf', 'sub', 'gua', 'jti']
];