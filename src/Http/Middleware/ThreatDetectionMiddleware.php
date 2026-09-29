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

    /**
     * Inspect the request, then hand it on — once.
     *
     * $next is called in exactly one place, outside the try. The early exits
     * used to return $next($request) from inside it, so when the application
     * threw on one of those paths the catch took its exception for a
     * detection failure and called $next($request) a second time: the
     * controller ran twice. Only the inspection is guarded; what the
     * application does is its own.
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            $this->inspect($request);
        } catch (\Throwable $e) {
            // Guarded: if the log cannot be written, logging here would throw
            // out of this catch and fail the request — the one thing this
            // middleware must never do.
            $this->logQuietly('ThreatDetectionMiddleware Error: ' . $e->getMessage());
        }

        return $next($request);
    }

    private function inspect(Request $request): void
    {
        if (!config('threat-detection.enabled') ||
            (config('threat-detection.enabled_environments') &&
            !in_array(app()->environment(), config('threat-detection.enabled_environments')))) {
            return;
        }

        $ip = (string) $request->ip();
        if ($this->detector->isWhitelisted($ip)) {
            return;
        }

        $uri = ltrim($request->path(), '/');

        // Whitelist mode: if only_paths is configured, skip everything not matching.
        //
        // The router matches the decoded path, so a scoped route is still
        // in scope when its path arrives percent-encoded: either spelling
        // brings it in. The lists below that narrow scanning compare the
        // raw path only, so an encoding can widen what is scanned and
        // never narrow it.
        $onlyPaths = config('threat-detection.only_paths', []);
        if (!empty($onlyPaths)) {
            $spellings = array_unique([$uri, rawurldecode($uri)]);
            $matched = false;
            foreach ($onlyPaths as $onlyPath) {
                foreach ($spellings as $spelling) {
                    if (fnmatch($onlyPath, $spelling)) {
                        $matched = true;
                        break 2;
                    }
                }
            }
            if (!$matched) {
                return;
            }
        }

        // Blacklist mode: skip paths matching skip_paths
        foreach (config('threat-detection.skip_paths', []) as $skip) {
            if (fnmatch($skip, $uri)) {
                return;
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
                $this->logQuietly('Threat detection: reading the ai-guard verdict failed: ' . $e->getMessage());
            }
        }

        $this->detector->detectAndLogFromRequest($request);
    }

    private function logQuietly(string $message): void
    {
        try {
            Log::error($message);
        } catch (\Throwable) {
            // The request comes first.
        }
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
