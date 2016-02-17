# Lumen JWT Auth Guard Driver

This is a Guard driver for Lumen that adds JWT support using the Laravel `Auth` class. All the heavy lifting is from
[lcobucci/jwt](https://github.com/lcobucci/jwt).

[![Latest Stable Version](https://poser.pugx.org/canis/lumen-jwt-auth/v/stable)](https://packagist.org/packages/canis/lumen-jwt-auth)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/canis-io/lumen-jwt-auth/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/canis-io/lumen-jwt-auth/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/canis-io/lumen-jwt-auth/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/canis-io/lumen-jwt-auth/?branch=master)
[![Build Status](https://travis-ci.org/canis-io/lumen-jwt-auth.svg)](https://travis-ci.org/canis-io/lumen-jwt-auth)
[![License](https://poser.pugx.org/canis/lumen-jwt-auth/license)](https://packagist.org/packages/canis/lumen-jwt-auth)

Installation
------------

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```
php composer.phar require --prefer-dist canis/lumen-jwt-auth
```

or add

```
"canis/lumen-jwt-auth": "^1.0"
```

to the require section of your composer.json.

Copy `config/jwt.php` to your Lumen application's `config` directory. In your local `.env` file, set values for `JWT_ISSUER` and `JWT_SECRET`.

Documentation
-------------
In your `bootstrap/app.php` file, add:

```php
$app->register(\Canis\Lumen\Jwt\ServiceProvider::class);
```

Sample `config/auth.php` file (with multiple providers):

```php
<?php
return [
    'defaults' => [
        'guard' => env('AUTH_GUARD', 'user'),
    ],
    'guards' => [
        'user' => [
            'driver' => 'jwt',
            'provider' => 'user',
        ],
        'client' => [
            'driver' => 'jwt',
            'provider' => 'client',
        ],
    ],
    'providers' => [
        'user' => [
            'driver' => 'eloquent',
            'model' => App\Models\User::class
        ],
        'client' => [
            'driver' => 'eloquent',
            'model' => App\Models\Client::class
        ]
    ]
];
```

You can use the Authenticate middleware found in Lumen's skeleton (included below). Once loaded as `auth` in the `routeMiddleware`, you can add `auth` to the routes you'd like to use. If you want to specify the guard (see the `auth.php` file above), append it like so: `auth:user` or `auth:client`.

```php
<?php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Factory as Auth;

class Authenticate
{
    /**
     * The authentication guard factory instance.
     *
     * @var \Illuminate\Contracts\Auth\Factory
     */
    protected $auth;

    /**
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @return void
     */
    public function __construct(Auth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {
        if ($this->auth->guard($guard)->guest()) {
            return response('Unauthorized.', 401);
        }
        return $next($request);
    }
}
```

## Security Vulnerabilities

If you discover a security vulnerability within this library, please send an e-mail to security@canis.io. All security vulnerabilities will be promptly addressed.

## License

This library is open-sourced software licensed under the [MIT license](http://opensource.org/licenses/MIT).
