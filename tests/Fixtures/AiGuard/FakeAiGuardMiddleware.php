<?php

namespace JayAnta\ThreatDetection\Tests\Fixtures\AiGuard;

use Illuminate\Http\Request;
use JayAnta\ThreatDetection\Integration\AiGuardContract;

/** Leaves ai-guard's verdict on the request, in the shape its README documents. */
final class FakeAiGuardMiddleware
{
    public function handle(Request $request, \Closure $next): mixed
    {
        $request->attributes->set(AiGuardContract::REQUEST_ATTRIBUTE, [
            'schema' => AiGuardContract::SCHEMA,
            'bot' => ['category' => 'ai_agents', 'token' => null, 'identity' => 'chatgpt.com'],
            'verification' => ['status' => 'verified', 'method' => 'web_bot_auth'],
            'evaluated_at' => now()->toIso8601String(),
        ]);

        return $next($request);
    }
}
