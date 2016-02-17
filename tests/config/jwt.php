<?php
return [
    'issuer' => 'test.com',
    'secret' => 'secret',
    'expOffset' => 3600,
    'requiredClaims' => ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti']
];
