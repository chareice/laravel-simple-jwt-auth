<?php

namespace Chareice\SimpleJwtAuth;

use Chareice\SimpleJwtAuth\Contracts\JWTSubject;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;

class JwtGuard implements Guard
{
    use GuardHelpers;

    protected JWTService $JWTService;
    protected string $inputKey;
    protected Request $request;
    protected Authenticatable $lastAttempted;

    public function __construct(
        JWTService $JWTService,
        Request $request,
        UserProvider $provider,
        string $inputKey = 'token'
    )
    {
        $this->request = $request;
        $this->provider = $provider;
        $this->inputKey = $inputKey;
        $this->JWTService = $JWTService;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user(): ?\Illuminate\Contracts\Auth\Authenticatable
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        $token = $this->getTokenForRequest();

        if (is_null($token)) {
            return null;
        }

        $payload = $this->getSubFromToken($token);

        return $this->user = $this->provider->retrieveById($payload[$this->JWTService->getSubKey()]);
    }

    protected function getSubFromToken(string $token)
    {
        return $this->JWTService->tokenPayload($token);
    }

    public function getTokenForRequest()
    {
        $request = request();
        $token = $request->query($this->inputKey);

        if (empty($token)) {
            $token = $request->input($this->inputKey);
        }

        if (empty($token)) {
            $token = $request->bearerToken();
        }

        if (empty($token)) {
            $token = $request->getPassword();
        }

        return $token;
    }

    public function validate(array $credentials = [])
    {
        $authenticatable = $this->provider->retrieveByCredentials($credentials);

        if (is_null($authenticatable)) {
            return false;
        }

        return $this->provider->validateCredentials($authenticatable, $credentials);
    }

    public function login(JWTSubject $subject, $meta = []): string
    {
        $token = $this->JWTService->tokenFromSubject($subject, $meta);
        $this->setUser($subject);
        return $token;
    }

    /**
     * Attempt to authenticate the user using the given credentials and return the token.
     *
     * @param  array  $credentials
     * @param  bool  $login
     *
     * @return bool|string
     */
    public function attempt(array $credentials = [], $login = true)
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            return $login ? $this->login($user) : true;
        }

        return false;
    }


    protected function hasValidCredentials($user, $credentials): bool
    {
        return $user !== null && $this->provider->validateCredentials($user, $credentials);
    }


    public function setRequest(Request $request)
    {
        $this->request = $request;
        // 新的Request 置空User
        $this->user = null;
        return $this;
    }

    public function setProvider(UserProvider $provider)
    {
        $this->provider = $provider;

        return $this;
    }
}