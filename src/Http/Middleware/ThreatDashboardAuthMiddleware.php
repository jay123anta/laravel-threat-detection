<?php

namespace JayAnta\ThreatDetection\Http\Middleware;

use Closure;
use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use JayAnta\ThreatDetection\Support\LogsQuietly;
use Symfony\Component\HttpFoundation\IpUtils;

class ThreatDashboardAuthMiddleware
{
    use LogsQuietly;

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

        // TD-008. A write here disables a detection for everyone, permanently,
        // and leaves nothing behind that looks like an attack. The write routes
        // sit in Laravel's `api` group, which is stateless by design and
        // carries no VerifyCsrfToken — correct for token authentication, wrong
        // the moment the endpoints are reached with cookies, which is what the
        // Sanctum-absent fallback produces.
        //
        // Checked before the guard so a forged request is refused before any
        // authorization work happens, and only for requests that actually
        // carry a session: a bearer token is not attached by a browser to a
        // cross-site request, so demanding a CSRF token from stateless callers
        // would break every legitimate API client and protect no one.
        if ($isWrite) {
            $this->verifyCsrfForCookieAuthenticatedWrite($request);
        }

        $guard = config("threat-detection.{$context}.{$key}", $isWrite ? 'role' : 'none');

        if ($guard === 'none') {
            // Log warning once per day — nudge users to configure auth
            $cacheKey = "threat_dashboard_auth_warning_{$context}" . ($isWrite ? '_write' : '');
            if (!Cache::has($cacheKey)) {
                $what = $isWrite
                    ? "{$context} write endpoints (mark false positive, delete exclusion rule) are"
                    : "{$context} is";
                self::logQuietly('warning', "Threat detection {$what} accessible without authentication. Set {$envVar} in your .env.");
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
                self::logQuietly('warning', "Threat detection {$context} " . ($isWrite ? 'write_guard' : 'guard')
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
                self::logQuietly('warning', "Threat detection {$context} guard is 'ip' but no allowed_ips are configured. Denying access rather than granting it to everyone.");
                abort(403, 'IP not allowed');
            }
            if (!IpUtils::checkIp($request->ip(), $allowedIps)) {
                abort(403, 'IP not allowed');
            }

            return $next($request);
        }

        // Unknown guard value (typo, unsupported mode): fail closed rather than
        // silently granting access to a security dashboard.
        self::logQuietly('warning', "Threat detection {$context} " . ($isWrite ? 'write_guard' : 'guard')
            . " '{$guard}' is not recognised (expected none|auth|role|ip). Denying access.");
        abort(403, 'Unauthorized');
    }

    /**
     * Reject a state-changing request that carries a session but no matching
     * CSRF token.
     *
     * Laravel's own VerifyCsrfToken is not delegated to here for two reasons:
     * it short-circuits whenever the application is running unit tests, which
     * would make every test of this behaviour vacuous; and the application's
     * subclass carries an $except list that has nothing to do with these
     * routes.
     *
     * Three token sources are accepted, matching what VerifyCsrfToken itself
     * reads: the _token form field, the X-CSRF-TOKEN header that the shipped
     * dashboard sends, and the encrypted X-XSRF-TOKEN header that axios-based
     * clients send from the cookie of the same name. Missing the third would
     * break an SPA that works today.
     */
    private function verifyCsrfForCookieAuthenticatedWrite(Request $request): void
    {
        // No session means no cookie a third-party page could ride on.
        if (!$request->hasSession() || !$request->session()->isStarted()) {
            return;
        }

        if (in_array($request->getMethod(), ['GET', 'HEAD', 'OPTIONS'], true)) {
            return;
        }

        $expected = (string) $request->session()->token();

        // A session with no token cannot be verified, so it is refused rather
        // than waved through.
        if ($expected === '' || !hash_equals($expected, (string) $this->csrfTokenFrom($request))) {
            abort(419, 'CSRF token mismatch.');
        }
    }

    private function csrfTokenFrom(Request $request): string
    {
        $token = $request->input('_token') ?: $request->header('X-CSRF-TOKEN');

        if (is_string($token) && $token !== '') {
            return $token;
        }

        $encrypted = $request->header('X-XSRF-TOKEN');

        if (!is_string($encrypted) || $encrypted === '') {
            return '';
        }

        try {
            $decrypted = Crypt::decrypt($encrypted, false);
        } catch (\Throwable $e) {
            return '';
        }

        // Laravel prefixes cookie values with an HMAC of the cookie name.
        // Referenced as a string so Pint's import fixer cannot hoist an
        // optional class into a use statement.
        if (class_exists('Illuminate\Cookie\CookieValuePrefix')) {
            $decrypted = CookieValuePrefix::remove($decrypted);
        }

        return (string) $decrypted;
    }
}
