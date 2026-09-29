<?php

namespace JayAnta\ThreatDetection\Integration;

use Illuminate\Http\Request;
use JayAnta\ThreatDetection\Services\ActorAttributionStore;
use JayAnta\ThreatDetection\Support\LogsQuietly;

/**
 * Translates an ai-guard verdict into this package's own vocabulary, and stops
 * there.
 *
 * Two channels, because neither is sufficient alone:
 *
 *   - **The events.** They fire whenever ai-guard evaluates a request, so they
 *     work however the two packages' middleware are ordered. They can be
 *     switched off at ai-guard's end.
 *   - **The request attribute.** Always set, even with their events disabled,
 *     but only readable once their middleware has run. If this package's
 *     middleware runs first, there is nothing there yet.
 *
 * Reading both means the integration works in either order and under either
 * setting, and the store collapses the duplicates.
 *
 * Every payload is type-checked field by field. It arrives from another
 * package across a string-keyed boundary, which is exactly the situation where
 * assuming a shape gets someone a TypeError in production.
 */
class AiGuardVerdictListener
{
    use LogsQuietly;

    public function __construct(private ActorAttributionStore $store) {}

    /**
     * An ai-guard interop event.
     *
     * Untyped on purpose: the class is not imported and may not exist, the
     * contract is its *properties* rather than its type, and a type error
     * here would be raised inside another package's dispatch loop. ai-guard
     * promises to catch a throwing listener, but this package should not need
     * another one to contain its failures — so nothing escapes this method.
     */
    public function handle(mixed $event): void
    {
        try {
            if (!is_object($event) || ($event->schema ?? null) !== AiGuardContract::SCHEMA) {
                return;
            }

            $ip = $event->ip ?? null;

            if (!is_string($ip) || $ip === '') {
                return;
            }

            $this->store->remember($ip, [
                'status' => $this->translateStatus($event->status ?? null),
                'category' => $this->stringOrNull($event->category ?? null),
                'identity' => $this->stringOrNull($event->identity ?? null),
            ]);
        } catch (\Throwable $e) {
            self::logQuietly('error', 'Threat detection: an ai-guard verdict could not be read: ' . $e->getMessage());
        }
    }

    /** The same verdict, taken from the request when ai-guard's middleware got there first. */
    public function ingestRequest(Request $request): void
    {
        $verdict = $request->attributes->get(AiGuardContract::REQUEST_ATTRIBUTE);

        if (!is_array($verdict) || ($verdict['schema'] ?? null) !== AiGuardContract::SCHEMA) {
            return;
        }

        $bot = is_array($verdict['bot'] ?? null) ? $verdict['bot'] : [];
        $verification = is_array($verdict['verification'] ?? null) ? $verdict['verification'] : [];

        $ip = (string) $request->ip();

        if ($ip === '') {
            return;
        }

        $this->store->remember($ip, [
            'status' => $this->translateStatus($verification['status'] ?? null),
            'category' => $this->stringOrNull($bot['category'] ?? null),
            'identity' => $this->stringOrNull($bot['identity'] ?? null),
        ]);
    }

    /**
     * ai-guard's status vocabulary into ours.
     *
     * The two spellings happen to coincide today, which is exactly why the
     * translation is written out rather than assumed: their contract allows
     * new enum values within v1, and if a value is ever renamed there this is
     * the single line that changes. Anything unrecognised is carried through
     * untouched and read as "unknown" downstream — never rejected.
     */
    private function translateStatus(mixed $value): ?string
    {
        $status = $this->stringOrNull($value);

        return match ($status) {
            AiGuardContract::STATUS_VERIFIED => ActorAttributionStore::STATUS_VERIFIED,
            AiGuardContract::STATUS_SPOOFED => ActorAttributionStore::STATUS_SPOOFED,
            default => $status,
        };
    }

    private function stringOrNull(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
