<?php


namespace Chareice\SimpleJwtAuth;


use Chareice\SimpleJwtAuth\Contracts\JWTSubject;
use Firebase\JWT\JWT;

class JWTService
{
  protected string $JWTSecret;
  protected string $subKey;

  public function __construct(string $secret, string $subKey)
  {
    $this->JWTSecret = $secret;
    $this->subKey = $subKey;
  }

  /**
   * encode jwt token from jwt subject
   * @param JWTSubject $subject
   * @return string
   */
  public function tokenFromSubject(JWTSubject $subject) : string
  {
    return JWT::encode([
      $this->getSubKey() => $subject->getJWTIdentifier()
    ], $this->JWTSecret);
  }

  /**
   * decode jwt payload from jwt token
   * @param string $token
   * @return mixed
   */
  public function tokenPayload(string $token)
  {
    return (array) JWT::decode($token, $this->JWTSecret, ['HS256']);
  }

  public function getSubKey() : string
  {
    return $this->subKey;
  }
}