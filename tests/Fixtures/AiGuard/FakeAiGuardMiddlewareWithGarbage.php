<?php

namespace JayAnta\ThreatDetection\Tests\Fixtures\AiGuard;

use Illuminate\Http\Request;
use JayAnta\ThreatDetection\Integration\AiGuardContract;

final class FakeAiGuardMiddlewareWithGarbage
{
    public function handle(Request $request, \Closure $next): mixed
    {
        $request->attributes->set(AiGuardContract::REQUEST_ATTRIBUTE, [
            'schema' => AiGuardContract::SCHEMA,
            'bot' => new \stdClass,
            'verification' => ['status' => ['nested' => 'array']],
        ]);

        return $next($request);
    }
}
