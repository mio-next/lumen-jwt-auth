<?php
/**
 * @copyright Copyright (c) 2016 Canis.io
 * @license   MIT
 */
namespace Canis\Lumen\Jwt;

use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Guard as GaurdContract;
use Canis\Lumen\Jwt\Exceptions\InvalidTokenException;
use Canis\Lumen\Jwt\Exceptions\InvalidAdapterException;
use Canis\Lumen\Jwt\Contracts\AdapterFactory as AdapterFactoryContract;
use Canis\Lumen\Jwt\Contracts\Processor as ProcessorContract;

abstract class BaseGuard
    implements GaurdContract, GuardInterface
{
    use GuardHelpers;

    /**
     * @var Request
     */
    protected $request;

    /**
     * Constructor
     * 
     * @param UserProvider $provider
     * @param Request      $request
     */
    public function __construct(UserProvider $provider, Request $request)
    {
        $this->request = $request;
        $this->provider = $provider;
    }

    /**
     * Returns the adapter class name to use
     * 
     * @return string
     */
    public function getAdapterFactoryClass()
    {
        $config = config('jwt');
        if (!isset($config['adapter'])) {
            $config['adapter'] = 'lcobucci';
        }
        if (class_exists($config['adapter'])) {
            $factoryClass = $config['adapter'];
        } else {
            $factoryClass = 'Canis\Lumen\Jwt\Adapters\\' . ucfirst($config['adapter']) . '\Factory';
            if (!class_exists($factoryClass)) {
                throw new InvalidAdapterException("{$config['adapter']} is not available");
            }
        }
        return $factoryClass;
    }

    /**
     * Returns the adapter factory object
     * 
     * @return AdapterFactoryContract
     */
    protected function getAdapterFactory()
    {
        static $factory;
        if (!isset($factory)) {
            $config = config('jwt');
            $factoryClass = $this->getAdapterFactoryClass();
            $factory = new $factoryClass($config);
        }
        return $factory;
    }

    /**
     * Returns a token processor from the adapter factory
     * 
     * @return ProcessorContract
     */
    protected function getProcessor()
    {
        return $this->getAdapterFactory()->getProcessor();
    }

    /**
     * Returns a token generator from the adapter factory
     * 
     * @return GeneratorContract
     */
    protected function getGenerator()
    {
        return $this->getAdapterFactory()->getGenerator();
    }

    /**
     * Gets the provider
     * 
     * @return UserProvider
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * @inheritdoc
     */
    public function user()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }
        $user = null;
        $token = $this->getBearerToken();
        if ($token !== false) {
            $user = $this->getProvider()->retrieveById($token->getClaim('sub'));
        }
        return $this->user = $user;
    }

    /**
     * Get's the bearer token from the request header
     * 
     * @return Token
     */
    public function getBearerToken()
    {
        $authHeader = $this->request->headers->get('Authorization');
        if (empty($authHeader)) {
            return false;
        }
        if (!Str::startsWith(strtolower($authHeader), 'bearer')) {
            return false;
        }
        $token = trim(str_ireplace('bearer', '', $authHeader));
        $processor = $this->getProcessor();
        return $processor($token);
    }

    /**
     * @inheritdoc
     */
    public function validate(array $credentials = [])
    {
        $user = $this->getProvider()->retrieveByCredentials($credentials);
        if ($this->hasValidCredentials($user, $credentials)) {
            return true;
        }
        return false;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param  Authenticatable|null  $user
     * @param  array  $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        return !is_null($user) && $this->getProvider()->validateCredentials($user, $credentials);
    }

    /**
     * Sets the Request
     * 
     * @param Request $request
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Gets the request
     * 
     * @return Request
     */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array  $credentials
     * @return bool|string
     */
    public function attempt(array $credentials = [])
    {
        $user = $this->getProvider()->retrieveByCredentials($credentials);
        if ($this->hasValidCredentials($user, $credentials)) {
            $tokenGenerator = $this->getGenerator();
            $claims = $user->getJWTClaims();
            $claims['sub'] = $user->getJWTSubject();
            $claims['type'] = $user->getJWTSubjectType();
            if (!($token = $tokenGenerator($claims))) {
                throw new InvalidTokenException("Unable to generate token");
            }
            return $token;
        }
        return false;
    }
}
