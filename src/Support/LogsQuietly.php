<?php

namespace JayAnta\ThreatDetection\Support;

use Illuminate\Support\Facades\Log;

/**
 * Logging that cannot throw.
 *
 * An unwritable log file is a common deployment mistake, and Monolog throws
 * when it cannot open its file. Inside a request that throw used to lose the
 * detection it was describing, or escape a catch and fail the application's
 * request — the one thing a passive detector must never do. Outside one it
 * turned finished work into failures: a queued write retried after it had
 * succeeded, a deleted rule reported as an error, every artisan command dying
 * at boot over a warning. The work is the record; the log line is a courtesy.
 *
 * Called through the facade's own info(), warning() and error(), so anything
 * that observes those calls observes these.
 */
trait LogsQuietly
{
    /**
     * @param  array<string, mixed>  $context
     */
    protected static function logQuietly(string $level, string $message, array $context = []): void
    {
        try {
            match ($level) {
                'error' => Log::error($message, $context),
                'info' => Log::info($message, $context),
                default => Log::warning($message, $context),
            };
        } catch (\Throwable) {
            // Nothing else to tell, and nowhere to tell it.
        }
    }
}
