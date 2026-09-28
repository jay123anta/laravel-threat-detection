<?php

namespace JayAnta\ThreatDetection\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class ThreatStatsCommand extends Command
{
    protected $signature = 'threat-detection:stats';

    protected $description = 'Display a quick stats summary of threat logs';

    public function handle(): int
    {
        $table = config('threat-detection.table_name', 'threat_logs');

        try {
            $todayDate = today()->toDateString();
            $lastHourTime = now()->subHour();

            // created_at's calendar day on every driver. SQL Server has no
            // DATE() function, and SQLite has no DATE type to CAST to — the
            // same split ThreatLogController::day() makes.
            $day = DB::connection()->getDriverName() === 'sqlite'
                ? 'DATE(created_at)'
                : 'CAST(created_at AS DATE)';

            $row = DB::table($table)
                ->selectRaw('COUNT(*) as total')
                ->selectRaw("SUM(CASE WHEN threat_level = 'high' THEN 1 ELSE 0 END) as high")
                ->selectRaw("SUM(CASE WHEN threat_level = 'medium' THEN 1 ELSE 0 END) as medium")
                ->selectRaw("SUM(CASE WHEN threat_level = 'low' THEN 1 ELSE 0 END) as low")
                ->selectRaw('COUNT(DISTINCT ip_address) as unique_ips')
                ->selectRaw('SUM(CASE WHEN ' . $day . ' = ? THEN 1 ELSE 0 END) as today', [$todayDate])
                ->selectRaw('SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) as last_hour', [$lastHourTime])
                ->first();
        } catch (\Throwable $e) {
            $this->error("Could not query the '{$table}' table. Have you run the migrations?");
            $this->line('  Run: php artisan vendor:publish --tag=threat-detection-migrations && php artisan migrate');

            return 1;
        }

        $this->newLine();
        $this->info('=== Threat Detection Stats ===');
        $this->newLine();

        $this->table(
            ['Metric', 'Count'],
            [
                ['Recorded Detections', (int) $row->total],
                ['High Severity', (int) $row->high],
                ['Medium Severity', (int) $row->medium],
                ['Low Severity', (int) $row->low],
                ['Unique IPs', (int) $row->unique_ips],
                ['Today', (int) $row->today],
                ['Last Hour', (int) $row->last_hour],
            ]
        );

        /*
         * TD-010. These are rows, not attempts.
         *
         * A detection is written once per IP per threat type per five minutes;
         * everything else inside that window is deduplicated and never reaches
         * the table. That is deliberate — it is what stops a flood turning into
         * a write per request — but it means twenty-five identical injections
         * from one address appear here as one, and neither volume nor
         * escalation can be read off these numbers.
         *
         * Said plainly at the point the number is presented, because "Total
         * Threats" invited exactly the wrong reading.
         */
        $this->line('  Counts are recorded detections, deduplicated per IP per type per 5 minutes.');
        $this->line('  Repeated attempts inside that window are not counted separately.');

        $topIps = DB::table($table)
            ->select('ip_address', DB::raw('COUNT(*) as count'))
            ->groupBy('ip_address')
            ->orderByDesc('count')
            ->limit(5)
            ->get();

        if ($topIps->isNotEmpty()) {
            $this->newLine();
            $this->info('Top 5 Offending IPs:');
            $this->table(
                ['IP Address', 'Threat Count'],
                $topIps->map(fn ($r) => [$r->ip_address, $r->count])->toArray()
            );
        }

        $topTypes = DB::table($table)
            ->select('type', DB::raw('COUNT(*) as count'))
            ->groupBy('type')
            ->orderByDesc('count')
            ->limit(5)
            ->get();

        if ($topTypes->isNotEmpty()) {
            $this->newLine();
            $this->info('Top 5 Threat Types:');
            $this->table(
                ['Type', 'Count'],
                $topTypes->map(fn ($r) => [$r->type, $r->count])->toArray()
            );
        }

        return 0;
    }
}
