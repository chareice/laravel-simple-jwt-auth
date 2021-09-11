<?php


namespace Chareice\SimpleJwtAuth\Contracts;


interface JWTSubject extends \Illuminate\Contracts\Auth\Authenticatable
{
  /**
   * Get the identifier that will be stored in the subject claim of the JWT.
   *
   * @return mixed
   */
  public function getJWTIdentifier();

}