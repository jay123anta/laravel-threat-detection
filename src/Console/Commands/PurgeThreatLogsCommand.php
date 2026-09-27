<?php

namespace JayAnta\ThreatDetection\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class PurgeThreatLogsCommand extends Command
{
    protected $signature = 'threat-detection:purge
                            {--days=30 : Delete logs older than this many days}';

    protected $description = 'Delete threat logs older than the specified number of days';

    public function handle(): int
    {
        $days = (int) $this->option('days');
        $table = config('threat-detection.table_name', 'threat_logs');
        $cutoff = now()->subDays($days);

        $count = DB::table($table)
            ->where('created_at', '<', $cutoff)
            ->count();

        if ($count === 0) {
            $this->info("No threat logs found older than {$days} days.");

            // Actor signals keep a separate, shorter retention, so they are
            // swept whether or not any log rows aged out. Doing this only
            // inside the delete branch meant an install whose threat_logs were
            // all recent never purged its signals at all — and signals are the
            // table that grows fastest.
            $this->purgeActorSignals();

            return 0;
        }

        $this->warn("This will permanently delete {$count} threat log(s) older than {$days} days.");

        if (!$this->input->isInteractive() || $this->confirm('Are you sure you want to proceed?')) {
            $deleted = DB::table($table)
                ->where('created_at', '<', $cutoff)
                ->delete();

            $this->info("Successfully deleted {$deleted} threat log(s).");

            // Remove exclusion rules whose source threat no longer exists. Done
            // with a DB-side subquery so we never load every purged id into
            // memory (safe on very large tables).
            if (Schema::hasTable('threat_exclusion_rules')) {
                $orphaned = DB::table('threat_exclusion_rules')
                    ->whereNotNull('created_from_threat_id')
                    ->whereNotIn('created_from_threat_id', function ($q) use ($table) {
                        $q->select('id')->from($table);
                    })
                    ->delete();

                if ($orphaned > 0) {
                    $this->info("Removed {$orphaned} orphaned exclusion rule(s).");
                }
            }

            $this->purgeActorSignals();

            return 0;
        }

        $this->info('Purge cancelled.');

        return 0;
    }

    /**
     * Sweep actor signals on their own retention.
     *
     * They are attempt-level evidence — one row per distinct payload variant,
     * rather than one per detection — so they accumulate faster and go stale
     * sooner than the log they support. Tying them to --days would force an
     * operator to choose between a year of threat_logs and a year of raw
     * attempt rows.
     *
     * Cancelling the confirmation cancels this too: a "no" means no deletion.
     */
    private function purgeActorSignals(): void
    {
        $table = config('threat-detection.actor_signals.table', 'threat_actor_signals');
        $days = (int) config('threat-detection.actor_signals.retention_days', 7);

        if ($days < 0 || !Schema::hasTable($table)) {
            return;
        }

        $removed = DB::table($table)
            ->where('created_at', '<', now()->subDays($days))
            ->delete();

        if ($removed > 0) {
            $this->info("Removed {$removed} actor signal(s) older than {$days} days.");
        }
    }
}
