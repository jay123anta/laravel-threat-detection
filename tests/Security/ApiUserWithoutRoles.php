<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * An authenticated user with no role support at all — no hasRole() method —
 * which is what most applications' User model looks like.
 *
 * In a file of its own because PSR-4 resolves a class from its filename. It
 * used to be declared at the bottom of ApiAuthorizationTest.php, which meant it
 * only existed once that file had been loaded: CsrfOnWriteEndpointsTest passed
 * in a full run purely because "ApiAuthorization" sorts before "Csrf", and
 * errored on every test when run by itself.
 */
class ApiUserWithoutRoles implements Authenticatable
{
    /** markFalsePositive() reads $request->user()?->id. */
    public int $id = 1;

    public function getAuthIdentifierName()
    {
        return 'id';
    }

    public function getAuthIdentifier()
    {
        return 1;
    }

    public function getAuthPassword()
    {
        return '';
    }

    public function getAuthPasswordName()
    {
        return 'password';
    }

    public function getRememberToken()
    {
        return null;
    }

    public function setRememberToken($value) {}

    public function getRememberTokenName()
    {
        return 'remember_token';
    }
}
