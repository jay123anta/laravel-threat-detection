<?php

namespace JayAnta\ThreatDetection\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\IpUtils;

class ThreatDetectionMiddleware
{
    protected ThreatDetectionService $detector;

    public function __construct(ThreatDetectionService $detector)
    {
        $this->detector = $detector;
    }

    public function handle(Request $request, Closure $next)
    {
        try {
            if (!config('threat-detection.enabled') ||
                (config('threat-detection.enabled_environments') &&
                !in_array(app()->environment(), config('threat-detection.enabled_environments')))) {
                return $next($request);
            }

            $ip = $request->ip();
            if (IpUtils::checkIp($ip, config('threat-detection.whitelisted_ips', []))) {
                return $next($request);
            }

            $uri = ltrim($request->path(), '/');

            // Whitelist mode: if only_paths is configured, skip everything not matching
            $onlyPaths = config('threat-detection.only_paths', []);
            if (!empty($onlyPaths)) {
                $matched = false;
                foreach ($onlyPaths as $onlyPath) {
                    if (fnmatch($onlyPath, $uri)) {
                        $matched = true;
                        break;
                    }
                }
                if (!$matched) {
                    return $next($request);
                }
            }

            // Blacklist mode: skip paths matching skip_paths
            foreach (config('threat-detection.skip_paths', []) as $skip) {
                if (fnmatch($skip, $uri)) {
                    return $next($request);
                }
            }

            // Auth paths get relaxed PII detection
            $isAuthPath = false;
            foreach (config('threat-detection.auth_paths', []) as $authPath) {
                if (fnmatch($authPath, $uri)) {
                    $isAuthPath = true;
                    break;
                }
            }

            if ($isAuthPath) {
                $request->attributes->set('threat-detection:auth-path', true);
            }

            foreach (config('threat-detection.content_paths', []) as $contentPath) {
                if (fnmatch($contentPath, $uri)) {
                    $request->attributes->set('threat-detection:content-path', true);
                    break;
                }
            }

            $this->detector->detectAndLogFromRequest($request);

        } catch (\Throwable $e) {
            Log::error('ThreatDetectionMiddleware Error: ' . $e->getMessage());
        }

        return $next($request);
    }
}
