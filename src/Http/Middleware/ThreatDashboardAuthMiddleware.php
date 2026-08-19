<?php

namespace JayAnta\ThreatDetection\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\IpUtils;

class ThreatDashboardAuthMiddleware
{
    /**
     * Handle dashboard/API auth based on configurable guard.
     *
     * @param  string  $context  'dashboard' or 'api'
     * @param  string|null  $mode  'write' to use the stricter write_guard
     *
     * Reading threat data and *switching detection off* are different
     * privileges. Marking a false positive or deleting an exclusion rule
     * silences a detection type for everyone, so those routes are checked
     * against write_guard — which defaults to 'role' — while read routes keep
     * whatever `guard` is configured. That way an upgrade does not take the
     * dashboard away from an existing install; it only stops an ordinary
     * authenticated user from disabling a detection.
     */
    public function handle(Request $request, Closure $next, string $context = 'dashboard', ?string $mode = null)
    {
        $isWrite = $mode === 'write';
        $key = $isWrite ? 'write_guard' : 'guard';
        $envVar = 'THREAT_DETECTION_' . strtoupper($context) . ($isWrite ? '_WRITE_GUARD' : '_GUARD');

        $guard = config("threat-detection.{$context}.{$key}", $isWrite ? 'role' : 'none');

        if ($guard === 'none') {
            // Log warning once per day — nudge users to configure auth
            $cacheKey = "threat_dashboard_auth_warning_{$context}" . ($isWrite ? '_write' : '');
            if (!Cache::has($cacheKey)) {
                $what = $isWrite
                    ? "{$context} write endpoints (mark false positive, delete exclusion rule) are"
                    : "{$context} is";
                Log::warning("Threat detection {$what} accessible without authentication. Set {$envVar} in your .env.");
                Cache::put($cacheKey, true, now()->addDay());
            }

            return $next($request);
        }

        if ($guard === 'auth') {
            if (!Auth::check()) {
                abort(403, 'Unauthorized');
            }

            return $next($request);
        }

        if ($guard === 'role') {
            if (!Auth::check()) {
                abort(403, 'Unauthorized');
            }
            $role = config("threat-detection.{$context}.role", 'admin');
            $user = Auth::user();
            // Fail closed: if the user model has no hasRole() we cannot verify
            // the role, so deny rather than silently allow.
            if (!method_exists($user, 'hasRole')) {
                Log::warning("Threat detection {$context} " . ($isWrite ? 'write_guard' : 'guard')
                    . " is 'role' but the authenticated user model has no hasRole() method. Denying access. "
                    . "Install a roles package (e.g. spatie/laravel-permission), or set {$envVar} to 'auth'.");
                abort(403, 'Insufficient permissions');
            }
            if (!$user->hasRole($role)) {
                abort(403, 'Insufficient permissions');
            }

            return $next($request);
        }

        if ($guard === 'ip') {
            $allowedIps = config("threat-detection.{$context}.allowed_ips", []);
            if (empty($allowedIps)) {
                Log::warning("Threat detection {$context} guard is 'ip' but no allowed_ips are configured. Denying access rather than granting it to everyone.");
                abort(403, 'IP not allowed');
            }
            if (!IpUtils::checkIp($request->ip(), $allowedIps)) {
                abort(403, 'IP not allowed');
            }

            return $next($request);
        }

        // Unknown guard value (typo, unsupported mode): fail closed rather than
        // silently granting access to a security dashboard.
        Log::warning("Threat detection {$context} " . ($isWrite ? 'write_guard' : 'guard')
            . " '{$guard}' is not recognised (expected none|auth|role|ip). Denying access.");
        abort(403, 'Unauthorized');
    }
}
