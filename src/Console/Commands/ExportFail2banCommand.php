<?php

namespace JayAnta\ThreatDetection\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;

class ExportFail2banCommand extends Command
{
    protected $signature = 'threat-detection:export-fail2ban
        {--level= : Filter by threat level (high, medium, low)}
        {--since=24h : Time range (e.g., 1h, 24h, 7d, 30d)}
        {--min-hits=1 : Minimum number of threat entries for an IP}
        {--format=fail2ban : Output format (fail2ban or plain)}
        {--jail=threat-detection : Jail name for fail2ban format}';

    protected $description = 'Export detected threat IPs in fail2ban-compatible format';

    public function handle(): int
    {
        $ips = $this->withValidAddresses($this->getBlockableIps());

        if ($ips->isEmpty()) {
            $this->info('No IPs match the given filters.');

            return 0;
        }

        $format = $this->option('format');
        $filters = $this->buildFilterDescription();

        $jail = $this->validJailName($this->option('jail'));

        if ($jail === null) {
            $this->error('Invalid --jail name. A fail2ban jail is letters, digits, hyphens and underscores.');
            $this->line('  Given: ' . var_export($this->option('jail'), true));

            return 1;
        }

        if (($warning = $this->nonPublicWarning($ips)) !== null) {
            Log::warning('Threat detection: fail2ban export ' . $warning);
        }

        if ($format === 'plain') {
            $this->outputPlain($ips, $filters);
        } else {
            $this->outputFail2ban($ips, $filters, $jail);
        }

        return 0;
    }

    /**
     * TD-015. The jail name as given, or null if it is not one.
     *
     * This is interpolated into a #!/bin/bash script the operator runs as
     * root. The value comes from their own command line, so it is not an
     * attacker input and this is the lowest-severity finding in the audit —
     * but a fail2ban jail name has a known shape, the output is a root-run
     * script, and refusing anything else costs nothing.
     *
     * Rejected rather than escaped: a jail name containing a space or a
     * semicolon is a typo, and quoting it would produce a script that runs and
     * silently bans nothing.
     */
    private function validJailName(mixed $jail): ?string
    {
        return is_string($jail) && preg_match('/^[A-Za-z0-9_-]+$/', $jail) === 1
            ? $jail
            : null;
    }

    private function getBlockableIps()
    {
        $table = config('threat-detection.table_name', 'threat_logs');
        $cutoff = $this->parseSince($this->option('since'));
        $minHits = (int) $this->option('min-hits');
        $level = $this->option('level');

        $query = DB::table($table)
            ->select('ip_address', DB::raw('COUNT(*) as hits'), DB::raw('MAX(created_at) as last_seen'))
            ->where('created_at', '>=', $cutoff)
            ->groupBy('ip_address')
            ->having(DB::raw('COUNT(*)'), '>=', $minHits)
            ->orderByDesc('hits');

        // A row the operator marked as a false positive is their own statement
        // that it was not an attack. It must not ban anyone, nor count toward
        // --min-hits. Only where the column exists: it arrived with the v1.2
        // migration, and an install that never ran it can still export what
        // it has.
        if (Schema::hasColumn($table, 'is_false_positive')) {
            $query->where('is_false_positive', false);
        }

        if ($level) {
            $query->where('threat_level', $level);
        }

        return $query->get();
    }

    /**
     * TD-005. Drop any row whose ip_address is not an address, immediately
     * before it is written into generated output.
     *
     * This command emits a #!/bin/bash script that an operator runs as root, so
     * a newline in this column becomes a new command and a $(...) becomes a
     * substitution at run time. Today the column is only ever written from
     * $request->ip(), which Symfony validates — but that is a guarantee made in
     * a dependency, for one write path, and this file is the last place the
     * value can be checked before it leaves as a shell script.
     *
     * Skipping is announced, so a blocklist that loses entries says so.
     */
    private function withValidAddresses($ips)
    {
        $detector = app(ThreatDetectionService::class);

        return $ips->filter(function ($row) use ($detector) {
            if (filter_var((string) $row->ip_address, FILTER_VALIDATE_IP) !== false) {
                // An address the operator whitelisted is never theirs to ban.
                return !$detector->isWhitelisted((string) $row->ip_address);
            }

            Log::warning(
                'Threat detection: skipping a fail2ban row whose ip_address is not a valid IP. '
                . 'It was not written to the generated output. Value: '
                . var_export($row->ip_address, true)
            );

            return false;
        })->values();
    }

    private function parseSince(string $since): Carbon
    {
        if (preg_match('/^(\d+)h$/i', $since, $m)) {
            return now()->subHours((int) $m[1]);
        }
        if (preg_match('/^(\d+)d$/i', $since, $m)) {
            return now()->subDays((int) $m[1]);
        }
        if (preg_match('/^(\d+)w$/i', $since, $m)) {
            return now()->subWeeks((int) $m[1]);
        }

        return now()->subHours(24);
    }

    private function buildFilterDescription(): string
    {
        $parts = [];
        if ($this->option('level')) {
            $parts[] = 'level=' . $this->option('level');
        }
        $parts[] = 'since=' . $this->option('since');
        $parts[] = 'min-hits=' . $this->option('min-hits');

        // One line, whatever it was given. This is a comment in a script run
        // as root, and --since and --min-hits need not parse for rows to be
        // exported, so a newline in either would end the comment and put the
        // rest on a line of its own. Same reasoning as the jail name.
        return (string) preg_replace('/[^\x20-\x7E]/', '?', implode(', ', $parts));
    }

    /**
     * A comment naming the private or reserved addresses about to be
     * exported, or null when there are none.
     *
     * They are still exported: some installs mean to ban internal clients.
     * But the usual way one gets here is a proxy or load balancer that
     * TrustProxies does not know about, so every request appears to come from
     * it — and banning it blocks every client at once.
     */
    private function nonPublicWarning($ips): ?string
    {
        $nonPublic = $ips->pluck('ip_address')
            ->filter(fn ($ip) => filter_var((string) $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false)
            ->values();

        if ($nonPublic->isEmpty()) {
            return null;
        }

        $shown = $nonPublic->take(5)->implode(', ') . ($nonPublic->count() > 5 ? ', …' : '');

        return "WARNING: {$nonPublic->count()} private or reserved address(es) below ({$shown}). "
            . 'If one is your proxy or load balancer, banning it blocks every client: configure TrustProxies first.';
    }

    private function printNonPublicWarning($ips): void
    {
        if (($warning = $this->nonPublicWarning($ips)) !== null) {
            $this->line('# ' . $warning);
        }
    }

    private function outputFail2ban($ips, string $filters, string $jail): void
    {
        $this->line('#!/bin/bash');
        $this->line('# Generated by jayanta/laravel-threat-detection on ' . now()->toDateTimeString());
        $this->line('# Filters: ' . $filters);
        $this->line('# Total IPs: ' . $ips->count());
        $this->printNonPublicWarning($ips);
        $this->line('');

        foreach ($ips as $ip) {
            $this->line("fail2ban-client set {$jail} banip {$ip->ip_address}  # hits: {$ip->hits}, last: {$ip->last_seen}");
        }
    }

    private function outputPlain($ips, string $filters): void
    {
        $this->line('# Generated by jayanta/laravel-threat-detection on ' . now()->toDateTimeString());
        $this->line('# Filters: ' . $filters);
        $this->line('# Total IPs: ' . $ips->count());
        $this->printNonPublicWarning($ips);

        foreach ($ips as $ip) {
            $this->line($ip->ip_address);
        }
    }
}
