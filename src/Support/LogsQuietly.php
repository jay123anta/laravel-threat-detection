<?php

namespace JayAnta\ThreatDetection\Support;

use Illuminate\Support\Facades\Log;

/**
 * Logging that cannot throw, for everything that runs inside a request.
 *
 * An unwritable log file is a common deployment mistake, and Monolog throws
 * when it cannot open its file. On the request path that throw used to lose
 * the detection it was describing, or escape a catch and fail the
 * application's request — the one thing a passive detector must never do.
 * The row in the database is the record; the log line is a courtesy.
 *
 * Called through the facade's own warning() and error(), so anything that
 * observes those calls observes these.
 */
trait LogsQuietly
{
    protected static function logQuietly(string $level, string $message): void
    {
        try {
            match ($level) {
                'error' => Log::error($message),
                default => Log::warning($message),
            };
        } catch (\Throwable) {
            // Nothing else to tell, and nowhere to tell it.
        }
    }
}
