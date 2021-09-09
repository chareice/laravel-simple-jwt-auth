<?php
class TestSubject implements \Chareice\SimpleJwtAuth\Contracts\JWTSubject
{
  private int $id;
  public function __construct(int $id)
  {
    $this->id = $id;
  }

  public function getJWTIdentifier(): int
  {
    return $this->id;
  }
}

it("encode from JWTSubject", function () {
  $id = 100;
  $subject = new TestSubject($id);
  $JwtSecret = "test";

  $service = new \Chareice\SimpleJwtAuth\JWTService($JwtSecret);

  $token = $service->tokenFromSubject($subject);

  $this->assertTrue(is_string($token));

  $payload = $service->tokenPayload($token);
  $this->assertTrue(array_key_exists('id', $payload));
  $this->assertTrue($id === $payload['id']);
});