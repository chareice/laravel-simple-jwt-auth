<?php

class TestSubject implements \Chareice\SimpleJwtAuth\Contracts\JWTSubject
{
    use \Illuminate\Auth\Authenticatable;

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

    $service = new \Chareice\SimpleJwtAuth\JWTService($JwtSecret, 'id');

    $token = $service->tokenFromSubject($subject);

    $this->assertIsString($token);

    $payload = $service->tokenPayload($token);
    $this->assertTrue(array_key_exists('id', $payload));
    $this->assertTrue($id === $payload['id']);
});

it('should encode with meta data', function () {
    $id = 100;
    $subject = new TestSubject($id);
    $JwtSecret = "test";

    $meta = ['ab' => 'cd'];

    $service = new \Chareice\SimpleJwtAuth\JWTService($JwtSecret, 'id');

    $token = $service->tokenFromSubject($subject, $meta);

    $this->assertIsString($token);

    $payload = $service->tokenPayload($token);

    $this->assertTrue(array_key_exists('id', $payload));
    $this->assertTrue($id === $payload['id']);

    $this->assertTrue(array_key_exists('ab', $payload));
    $this->assertTrue('cd' === $payload['ab']);
});