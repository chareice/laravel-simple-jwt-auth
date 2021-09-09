<?php


namespace Chareice\SimpleJwtAuth;


use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class JWTServiceProvider extends ServiceProvider
{
  public function register()
  {
    $this->app->singleton('jwt', function() {
      return new JWTService(config('app.jwt_secret'));
    });
  }

  public function boot()
  {
    Auth::extend('simple-jwt', function (Application  $app, $name, array $config) {
      return new JwtGuard(
        $app['jwt'],
        Auth::createUserProvider($config['provider'])
      );
    });
  }
}