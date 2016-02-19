<?php
return [
    'issuer' => 'http://test.com',
    'secret' => 'super-secret-test',
    'expOffset' => 3600,
    'requiredClaims' => ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti'],
    'refreshOffsetAllowance' => 4000,
    'jtiInHeader' => false
];
