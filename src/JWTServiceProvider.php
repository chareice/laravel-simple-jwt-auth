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
      return new JWTService(config('app.jwt_secret'), config('app.jwt_sub_key', 'id'));
    });
  }

  public function boot()
  {
    Auth::extend('simple-jwt', function (Application  $app, $name, array $config) {
      $guard =  new JwtGuard(
        $app['jwt'],
        $app['request'],
        Auth::createUserProvider($config['provider'])
      );

      $app->refresh('request', $guard, 'setRequest');
      return $guard;
    });
  }
}