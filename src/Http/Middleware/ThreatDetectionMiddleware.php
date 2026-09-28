<?php

namespace JayAnta\ThreatDetection\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use JayAnta\ThreatDetection\Integration\AiGuardVerdictListener;
use JayAnta\ThreatDetection\Services\ProbeDetectorService;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

class ThreatDetectionMiddleware
{
    protected ThreatDetectionService $detector;

    protected ProbeDetectorService $probeDetector;

    public function __construct(ThreatDetectionService $detector, ProbeDetectorService $probeDetector)
    {
        $this->detector = $detector;
        $this->probeDetector = $probeDetector;
    }

    public function handle(Request $request, Closure $next)
    {
        try {
            if (!config('threat-detection.enabled') ||
                (config('threat-detection.enabled_environments') &&
                !in_array(app()->environment(), config('threat-detection.enabled_environments')))) {
                return $next($request);
            }

            $ip = (string) $request->ip();
            if ($this->detector->isWhitelisted($ip)) {
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

            // Probe detection: check if URI matches known vulnerable paths
            $probeResult = $this->probeDetector->detect($request->path());

            // The AI pack assumes the app does not serve these paths. When it
            // does — a tags API at /api/tags, a chat widget at /api/chat —
            // the request is the app's own traffic, not a hunt for Ollama.
            if (($probeResult['pack'] ?? null) === ProbeDetectorService::AI_PACK && $this->applicationServes($request)) {
                $probeResult = null;
            }

            if ($probeResult) {
                $request->attributes->set('threat-detection:probe', $probeResult);
            }

            // If ai-guard's middleware already evaluated this request, take
            // its verdict from the request rather than waiting for an event.
            // Costs one attribute lookup, and only when the operator asked.
            //
            // Guarded separately from detection, which runs next. Sharing the
            // outer try would mean any failure here — malformed data from
            // another package, say — silently skipped detection for the
            // request, and an optional hint must never cost the core its
            // evidence.
            if (config('threat-detection.ai_guard.enabled', false)) {
                try {
                    app(AiGuardVerdictListener::class)->ingestRequest($request);
                } catch (\Throwable $e) {
                    Log::error('Threat detection: reading the ai-guard verdict failed: ' . $e->getMessage());
                }
            }

            $this->detector->detectAndLogFromRequest($request);

        } catch (\Throwable $e) {
            Log::error('ThreatDetectionMiddleware Error: ' . $e->getMessage());
        }

        return $next($request);
    }

    /**
     * Does a real route serve this path?
     *
     * A fallback route answers every path, and so does a catch-all made of a
     * single parameter (an SPA's `{any}`); neither says this path is real, and
     * those are exactly the setups where the pack does its work. A path that
     * exists under another method is the app's own: the verb differs, the
     * endpoint does not.
     *
     * Asked only for an AI-pack hit, which ordinary traffic rarely produces,
     * and matched against the route table without dispatching anything.
     */
    private function applicationServes(Request $request): bool
    {
        try {
            $route = app('router')->getRoutes()->match($request);
        } catch (MethodNotAllowedHttpException) {
            return true;
        } catch (NotFoundHttpException) {
            return false;
        } catch (\Throwable) {
            // Anything else — an app route that cannot compile, say — must
            // not reach the outer catch, which would skip detection for the
            // whole request. Unknown is treated as unserved: logging a probe
            // the app might serve beats losing the request's evidence.
            return false;
        }

        if ($route->isFallback) {
            return false;
        }

        return !preg_match('#^\{[^/{}]+\??\}$#', trim($route->uri(), '/'));
    }
}
