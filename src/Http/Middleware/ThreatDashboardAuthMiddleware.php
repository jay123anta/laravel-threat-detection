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
     * @param string $context 'dashboard' or 'api'
     */
    public function handle(Request $request, Closure $next, string $context = 'dashboard')
    {
        $guard = config("threat-detection.{$context}.guard", 'none');

        if ($guard === 'none') {
            // Log warning once per day — nudge users to configure auth
            $cacheKey = "threat_dashboard_auth_warning_{$context}";
            if (!Cache::has($cacheKey)) {
                Log::warning("Threat detection {$context} is accessible without authentication. Set THREAT_DETECTION_" . strtoupper($context) . "_GUARD in your .env.");
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
                Log::warning("Threat detection {$context} guard is 'role' but the authenticated user model has no hasRole() method. Denying access. Install a roles package (e.g. spatie/laravel-permission) or switch the guard to 'auth'.");
                abort(403, 'Insufficient permissions');
            }
            if (!$user->hasRole($role)) {
                abort(403, 'Insufficient permissions');
            }
            return $next($request);
        }

        if ($guard === 'ip') {
            $allowedIps = config("threat-detection.{$context}.allowed_ips", []);
            if (!empty($allowedIps) && !IpUtils::checkIp($request->ip(), $allowedIps)) {
                abort(403, 'IP not allowed');
            }
            return $next($request);
        }

        // Unknown guard value (typo, unsupported mode): fail closed rather than
        // silently granting access to a security dashboard.
        Log::warning("Threat detection {$context} guard '{$guard}' is not recognised (expected none|auth|role|ip). Denying access.");
        abort(403, 'Unauthorized');
    }
}
