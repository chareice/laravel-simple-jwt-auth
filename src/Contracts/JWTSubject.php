<?php


namespace Chareice\SimpleJwtAuth\Contracts;


interface JWTSubject
{
  /**
   * Get the identifier that will be stored in the subject claim of the JWT.
   *
   * @return mixed
   */
  public function getJWTIdentifier();

}