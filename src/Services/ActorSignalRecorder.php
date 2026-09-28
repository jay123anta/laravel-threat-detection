<?php

namespace JayAnta\ThreatDetection\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;

/**
 * Records attempt-level evidence that threat_logs deliberately cannot hold.
 *
 * threat_logs keeps one row per IP per type per five minutes. That is correct
 * — it is what stops a flood becoming a write per request — but it means
 * twenty distinct encodings of one injection collapse into a single row, and
 * those nineteen suppressed attempts are the evidence that somebody is
 * iterating on a payload until it lands.
 *
 * So this runs *before* both of the gates that would hide it: before the
 * confidence floor, which returns early on low-scoring requests, and before
 * the five-minute deduplication.
 *
 * It is a recorder, not a detector. Nothing here reports a threat, raises a
 * level or changes what threat_logs receives. Detections read this table in a
 * later release; this increment only fills it.
 *
 * Three things bound the write volume:
 *
 *   - nothing is recorded for a request that matched no pattern, so clean
 *     traffic never touches the table;
 *   - a fingerprint already seen for an actor inside the dedupe window is not
 *     written again, so repeating one payload adds nothing and only genuinely
 *     new variants cost a row;
 *   - a hard per-actor ceiling per window, so an attacker cannot turn the
 *     table into a write amplifier with endless random payloads.
 */
class ActorSignalRecorder
{
    /**
     * Record the distinct normalised payloads behind this request's matches.
     *
     * @param  array<int, array{label: string, threat_level: string, source: string, context: string, fingerprint?: string, variant?: string}>  $matches
     */
    public function record(string $actorKey, array $matches): void
    {
        if (!config('threat-detection.actor_signals.enabled', false)) {
            return;
        }

        if ($actorKey === '' || $matches === []) {
            return;
        }

        try {
            $table = $this->table();

            if (!Schema::hasTable($table)) {
                $this->warnOnce(
                    'missing-table',
                    "Threat detection: actor_signals is enabled but the '{$table}' table does not exist. "
                    . 'Publish and run the package migrations, or set THREAT_DETECTION_ACTOR_SIGNALS=false.'
                );

                return;
            }

            $rows = $this->pendingRows($actorKey, $matches);

            if ($rows !== []) {
                DB::table($table)->insert($rows);
            }
        } catch (\Throwable $e) {
            // Same discipline as the rest of the package: a failure here is
            // recorded and swallowed. This is supplementary evidence, and it
            // must never cost the caller its own logging, let alone the
            // request.
            Log::error('Threat detection: actor signal write failed: ' . $e->getMessage());
        }
    }

    /**
     * The rows worth inserting: one per fingerprint not already seen for this
     * actor in the window, up to the per-actor ceiling.
     *
     * The cache marks are set as the rows are chosen rather than after the
     * insert. That is the opposite of how threat_logs defers its dedup mark,
     * and deliberately so: there the cost of a lost write is a missed
     * detection, while here it is one absent data point in a count, and
     * marking first keeps a burst of concurrent requests from each deciding to
     * write the same fingerprint.
     *
     * @param  array<int, array{label: string, context: string, fingerprint?: string, variant?: string}>  $matches
     * @return array<int, array<string, mixed>>
     */
    private function pendingRows(string $actorKey, array $matches): array
    {
        $dedupeMinutes = $this->positiveInt('dedupe_minutes', 60);
        $ceiling = $this->positiveInt('max_per_actor_per_window', 200);

        $now = now();
        $rows = [];
        $seenThisRequest = [];

        foreach ($matches as $match) {
            $fingerprint = $match['fingerprint'] ?? null;

            // Evasion matches carry no fingerprint: they describe the encoding
            // rather than the decoded payload, and encoding is the part that
            // varies by design.
            if (!is_string($fingerprint) || $fingerprint === '') {
                continue;
            }

            $variant = $match['variant'] ?? null;

            if (!is_string($variant) || $variant === '') {
                continue;
            }

            $label = (string) $match['label'];
            $context = (string) $match['context'];

            // Deduped on the *variant*, not the fingerprint: resending one
            // payload adds nothing, while a new encoding of the same attack
            // is the thing worth recording.
            $key = $variant . '|' . $label . '|' . $context;

            if (isset($seenThisRequest[$key])) {
                continue;
            }
            $seenThisRequest[$key] = true;

            $cacheKey = 'threat_actor_signal:' . sha1($actorKey . '|' . $key);

            if (Cache::has($cacheKey)) {
                continue;
            }

            if ($this->atCeiling($actorKey, $ceiling)) {
                $this->warnOnce(
                    'ceiling:' . $actorKey,
                    "Threat detection: actor {$actorKey} reached the actor_signals ceiling of {$ceiling} "
                    . 'for this window; further signals from it are not recorded.'
                );

                break;
            }

            Cache::put($cacheKey, true, $now->copy()->addMinutes($dedupeMinutes));

            $rows[] = [
                'actor_key' => mb_substr($actorKey, 0, 100),
                'fingerprint' => mb_substr($fingerprint, 0, 32),
                'variant' => mb_substr($variant, 0, 32),
                'label' => mb_substr($label, 0, 100),
                'context' => mb_substr($context, 0, 20),
                'observed_on' => $now->toDateString(),
                'created_at' => $now,
            ];
        }

        return $rows;
    }

    /**
     * Has this actor already written its allowance for the window?
     *
     * Counted in the cache rather than with a COUNT query, so a matched
     * request does not pay a read before its write. Same trade as the DDoS
     * counter, and the same caveat: on the array driver the counter is
     * per-process, so the ceiling only really binds on a shared store.
     */
    private function atCeiling(string $actorKey, int $ceiling): bool
    {
        $windowMinutes = $this->positiveInt('window_minutes', 60);
        $key = 'threat_actor_signal_count:' . sha1($actorKey);

        Cache::add($key, 0, now()->addMinutes($windowMinutes));
        $used = (int) Cache::get($key, 0);

        if ($used >= $ceiling) {
            return true;
        }

        Cache::increment($key);

        return false;
    }

    public function table(): string
    {
        $configured = config('threat-detection.actor_signals.table', 'threat_actor_signals');

        return is_string($configured) && $configured !== '' ? $configured : 'threat_actor_signals';
    }

    /**
     * A positive integer setting, or the default. Config arrives from .env as
     * strings, and a zero or negative window would either expire instantly or
     * never, neither of which anyone means.
     */
    private function positiveInt(string $key, int $default): int
    {
        $value = config("threat-detection.actor_signals.{$key}", $default);

        return is_numeric($value) && (int) $value > 0 ? (int) $value : $default;
    }

    /** @var array<string, true> */
    private static array $warned = [];

    /**
     * Distinct warnings remembered per process. The ceiling warning is keyed
     * by actor, and under Octane a worker lives for thousands of requests, so
     * an unbounded list would grow with every address that hit the ceiling.
     */
    private const MAX_WARNED = 256;

    private function warnOnce(string $key, string $message): void
    {
        if (isset(self::$warned[$key])) {
            return;
        }

        if (count(self::$warned) >= self::MAX_WARNED) {
            // Say once that the rest go unreported, then stay quiet.
            if (!isset(self::$warned['__overflow'])) {
                self::$warned['__overflow'] = true;
                Log::warning('Threat detection: further actor-signal warnings in this process are suppressed.');
            }

            return;
        }

        self::$warned[$key] = true;
        Log::warning($message);
    }

    /** Tests and Octane reloads need the warn-once flags cleared. */
    public static function flushCaches(): void
    {
        self::$warned = [];
    }
}
