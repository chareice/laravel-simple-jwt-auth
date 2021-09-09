<?php

namespace Chareice\SimpleJwtAuth;

use Chareice\SimpleJwtAuth\Contracts\JWTSubject;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;

class JwtGuard implements Guard
{
  use GuardHelpers;

  protected JWTService $JWTService;
  protected string $inputKey;

  public function __construct(
    JWTService $JWTService,
    UserProvider $provider,
    string $inputKey = 'token'
  )
  {
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

    return $this->user = $this->provider->retrieveById($payload['uid']);
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

  public function login(JWTSubject $subject): string
  {
    return $this->JWTService->tokenFromSubject($subject);
  }
}