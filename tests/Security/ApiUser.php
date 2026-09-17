<?php

namespace JayAnta\ThreatDetection\Tests\Security;

/**
 * An authenticated user that answers hasRole(), for exercising the `role`
 * guard. See ApiUserWithoutRoles for why this lives in its own file.
 */
class ApiUser extends ApiUserWithoutRoles
{
    public function __construct(private array $roles = []) {}

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles, true);
    }
}
