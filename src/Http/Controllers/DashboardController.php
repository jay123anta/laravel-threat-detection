<?php

namespace JayAnta\ThreatDetection\Http\Controllers;

use Illuminate\Routing\Controller;

class DashboardController extends Controller
{
    public function index()
    {
        $response = response()->view('threat-detection::dashboard', [
            'apiPrefix' => '/' . ltrim(config('threat-detection.api.prefix', 'api/threat-detection'), '/'),
        ]);

        if (config('threat-detection.dashboard.security_headers', true)) {
            $response->withHeaders($this->securityHeaders());
        }

        return $response;
    }

    /**
     * This page renders collected attack data — payloads, URLs and user agents
     * supplied by attackers — to an authenticated administrator. Sent as real
     * headers rather than a <meta> tag because frame-ancestors is ignored in
     * meta.
     *
     * 'unsafe-inline' and 'unsafe-eval' are required by Alpine 3 and the
     * dashboard's inline component script, so script-src is a allow-list of
     * origins rather than a strict policy. The clause that earns its keep is
     * connect-src 'self': even if one of the pinned CDN scripts were replaced,
     * it could not post this application's threat data to another origin.
     *
     * Set dashboard.security_headers to false if you have published and
     * customised the view to load assets from elsewhere.
     *
     * @return array<string, string>
     */
    protected function securityHeaders(): array
    {
        $csp = implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdn.tailwindcss.com",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self' data:",
            "connect-src 'self'",
            "form-action 'self'",
            "base-uri 'self'",
            "frame-ancestors 'none'",
        ]);

        return [
            'Content-Security-Policy' => $csp,
            'X-Frame-Options' => 'DENY',
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'no-referrer',
        ];
    }
}
