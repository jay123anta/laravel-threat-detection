<?php

namespace JayAnta\ThreatDetection\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * What a *second source* claimed about an actor's identity, kept for as long
 * as the risk score looks back.
 *
 * Nothing here mentions where the claim came from. One integration fills this
 * today; the scorer reads it and could not tell you which. That separation is
 * the point — it is what keeps a single optional integration from spreading
 * through the package.
 *
 * Cache-backed rather than a table: this is a hint with a lifetime measured in
 * minutes, not evidence. It is reconstructed from the next request if it is
 * lost, a cold cache simply removes the term from the score, and no migration
 * is imposed on anyone for an integration most installs will never enable.
 *
 * ── Why "spoofed" is sticky ────────────────────────────────────────────────
 *
 * An actor caught impersonating a crawler stays marked for the rest of the
 * window, even if a later request from the same address verifies cleanly.
 * Impersonation is not a state a client drifts in and out of innocently, and
 * the alternative — letting one clean verdict clear the record — hands an
 * attacker the erasure for free.
 */
class ActorAttributionStore
{
    /**
     * This package's own vocabulary for the two statuses it acts on. The
     * integration translates into these at the boundary, so nothing
     * downstream is pinned to another package's spelling.
     */
    public const STATUS_VERIFIED = 'verified';

    public const STATUS_SPOOFED = 'spoofed';

    /**
     * Record what was claimed about this actor.
     *
     * @param  array{status?: string|null, category?: string|null, identity?: string|null}  $attribution
     */
    public function remember(string $actorKey, array $attribution): void
    {
        if (!$this->enabled() || $actorKey === '') {
            return;
        }

        try {
            $status = $this->cleanString($attribution['status'] ?? null);

            $incoming = [
                'status' => $status,
                'category' => $this->cleanString($attribution['category'] ?? null),
                'identity' => $this->cleanString($attribution['identity'] ?? null),
            ];

            // Nothing was actually claimed. Writing it would only cost a
            // cache entry and teach the scorer nothing.
            if ($incoming['status'] === null && $incoming['category'] === null) {
                return;
            }

            $key = $this->key($actorKey);
            $existing = Cache::get($key);

            if (is_array($existing)
                && ($existing['status'] ?? null) === self::STATUS_SPOOFED
                && $status !== self::STATUS_SPOOFED
            ) {
                return;
            }

            Cache::put($key, $incoming, now()->addMinutes($this->ttlMinutes()));
        } catch (\Throwable $e) {
            // The same rule as everywhere else in this package: an optional
            // signal must never cost the caller anything, least of all the
            // request.
            Log::error('Threat detection: actor attribution write failed: ' . $e->getMessage());
        }
    }

    /**
     * What is known about this actor, or null when nothing is.
     *
     * @return array{status: string|null, category: string|null, identity: string|null}|null
     */
    public function forActor(string $actorKey): ?array
    {
        if (!$this->enabled() || $actorKey === '') {
            return null;
        }

        try {
            $stored = Cache::get($this->key($actorKey));

            if (!is_array($stored)) {
                return null;
            }

            return [
                'status' => $this->cleanString($stored['status'] ?? null),
                'category' => $this->cleanString($stored['category'] ?? null),
                'identity' => $this->cleanString($stored['identity'] ?? null),
            ];
        } catch (\Throwable $e) {
            Log::error('Threat detection: actor attribution read failed: ' . $e->getMessage());

            return null;
        }
    }

    public function forget(string $actorKey): void
    {
        try {
            Cache::forget($this->key($actorKey));
        } catch (\Throwable) {
            // Nothing depends on the removal succeeding.
        }
    }

    private function enabled(): bool
    {
        return (bool) config('threat-detection.ai_guard.enabled', false);
    }

    private function key(string $actorKey): string
    {
        return 'threat_actor_attribution:' . sha1($actorKey);
    }

    private function ttlMinutes(): int
    {
        $value = config('threat-detection.ai_guard.ttl_minutes', 60);

        return is_numeric($value) && (int) $value > 0 ? (int) $value : 60;
    }

    /**
     * Enum values arrive from another package and may be extended there at
     * any time. An unfamiliar value is carried through as-is and read as
     * "unknown" by whoever consumes it — never rejected, never an error.
     */
    private function cleanString(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        $trimmed = trim($value);

        return $trimmed === '' ? null : mb_substr($trimmed, 0, 64);
    }
}
