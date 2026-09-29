<?php

namespace JayAnta\ThreatDetection\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;

class EnrichThreatLogsCommand extends Command
{
    protected $signature = 'threat-detection:enrich
                            {--days=7 : Number of days to process}
                            {--force : Force re-enrich already enriched records}';

    protected $description = 'Enrich threat logs with geo-location and cloud provider data';

    /** Cloud provider keywords keyed by ISP/org substrings. */
    protected array $cloudIspKeywords = [
        'Amazon' => 'AWS',
        'AWS' => 'AWS',
        'EC2' => 'AWS',
        'Microsoft' => 'Azure',
        'Azure' => 'Azure',
        'Google Cloud' => 'GCP',
        'Google LLC' => 'GCP',
        'DigitalOcean' => 'DigitalOcean',
        'Linode' => 'Linode',
        'Akamai' => 'Linode',
        'Vultr' => 'Vultr',
        'Choopa' => 'Vultr',
        'OVH' => 'OVH',
        'Hetzner' => 'Hetzner',
        'Cloudflare' => 'Cloudflare',
        'Oracle Cloud' => 'Oracle',
        'Alibaba' => 'Alibaba',
        'Tencent Cloud' => 'Tencent',
    ];

    /** Known cloud provider IP prefixes. */
    protected array $cloudPrefixes = [
        'AWS' => ['18.', '54.'],
        'DigitalOcean' => ['139.59.', '167.99.', '167.172.', '157.230.', '159.65.', '134.209.', '164.90.'],
        'Linode' => ['139.162.', '172.104.', '172.105.', '45.33.', '45.56.', '45.79.'],
        'Vultr' => ['45.32.', '45.63.', '45.76.', '45.77.', '149.28.', '108.61.', '95.179.'],
    ];

    /**
     * Geo provider base URL.
     *
     * TD-013. The default is HTTPS. Over cleartext, the attacking IPs looked up
     * here are readable by anyone on the path, and — worse — the reply is
     * theirs to forge, and it is written into the database and shown on the
     * dashboard.
     *
     * ip-api.com's free tier answers 403 over TLS, so this default breaks
     * enrichment there. It breaks it *loudly*: handle() reports how many
     * lookups resolved and exits non-zero when none did, rather than printing
     * "Enrichment complete!" having enriched nothing. There is deliberately no
     * fallback to cleartext, since an attacker able to block the HTTPS request
     * would otherwise be handed the plaintext one.
     *
     * Free-tier users who accept the disclosure can set
     * THREAT_DETECTION_GEO_ENDPOINT back to http://ip-api.com/json. Enrichment
     * is opt-in either way: nothing is sent unless this command is run.
     */
    protected function endpoint(): string
    {
        return (string) config(
            'threat-detection.enrichment.endpoint',
            'https://ip-api.com/json'
        );
    }

    /** Whether the last enrichIp() call sent a request to the provider. */
    private bool $sentRequest = false;

    public function handle(): int
    {
        // Laravel's HTTP client is a Guzzle wrapper, and guzzle is a suggest
        // rather than a requirement — detection itself never makes a request.
        // Without it every lookup fails inside fetchGeoData()'s best-effort
        // catch, and this command would report success having enriched
        // nothing. Say so instead.
        if (!class_exists('GuzzleHttp\Client')) {
            $this->error('Geo enrichment needs an HTTP client, and guzzlehttp/guzzle is not installed.');
            $this->line('  Run: composer require guzzlehttp/guzzle');

            return 1;
        }

        $days = (int) $this->option('days');
        $force = $this->option('force');
        $table = config('threat-detection.table_name', 'threat_logs');

        $query = DB::table($table)
            ->where('created_at', '>=', now()->subDays($days))
            ->distinct();

        if (!$force) {
            $query->whereNull('country_code');
        }

        $ips = $query->pluck('ip_address');

        if ($ips->isEmpty()) {
            $this->info('No IPs to enrich.');

            return 0;
        }

        $endpoint = $this->endpoint();

        $this->info("Enriching {$ips->count()} unique IPs from the last {$days} days...");
        $this->line("  Provider: {$endpoint}");
        $this->line("  {$ips->count()} address(es) will be sent to this third party."
            . (str_starts_with($endpoint, 'http://') ? ' Note: over cleartext HTTP.' : ''));

        $bar = $this->output->createProgressBar($ips->count());

        $enriched = 0;
        $attempted = 0;

        foreach ($ips as $ip) {
            if ($this->isLookupCandidate($ip)) {
                $attempted++;
            }

            $this->sentRequest = false;
            $data = $this->enrichIp($ip);

            // A lookup that resolved nothing leaves country_code null. Counting
            // that separately is what lets a total failure be reported instead
            // of announced as success.
            if (($data['country_code'] ?? null) !== null) {
                $enriched++;
            }

            DB::table($table)
                ->where('ip_address', $ip)
                ->when(!$force, fn ($q) => $q->whereNull('country_code'))
                ->update($data);

            $bar->advance();

            // Rate limit: ~43 req/min (ip-api.com free tier allows 45/min).
            // Only after a request that was actually sent: a private address
            // is skipped and a cached answer asks nobody, and pausing for
            // those made a table of internal traffic take 1.4 s a row to
            // enrich nothing.
            if ($this->sentRequest) {
                usleep(1400000);
            }
        }

        $bar->finish();
        $this->newLine();

        /*
         * TD-013. A geo lookup is best-effort and its failure is swallowed, so
         * without this the command printed "Enrichment complete!" having
         * enriched nothing — the same silent success the missing-guzzle bug
         * produced in v1.7.2.
         *
         * It matters more now that the endpoint defaults to HTTPS:
         * ip-api.com's free tier answers 403 over TLS, so the most likely
         * reason for a total failure is exactly the change that made the
         * transport safe, and the operator needs to be told which trade they
         * are looking at rather than left with an empty dashboard.
         */
        if ($attempted > 0 && $enriched === 0) {
            $this->error("Enrichment failed: 0 of {$attempted} addresses were resolved.");
            $this->line('  Provider: ' . $endpoint);
            $this->line('  Every lookup failed. Common causes:');
            $this->line('   - ip-api.com answers 403 over HTTPS on the free tier.');
            $this->line('     Set THREAT_DETECTION_GEO_ENDPOINT to a provider that supports TLS,');
            $this->line('     or accept the disclosure and set it to http://ip-api.com/json.');
            $this->line('   - the provider is unreachable, or the rate limit is exhausted.');

            return 1;
        }

        $this->info("Enrichment complete! {$enriched} of {$attempted} addresses resolved"
            . ($attempted < $ips->count() ? ' (' . ($ips->count() - $attempted) . ' private or malformed, skipped).' : '.'));

        return 0;
    }

    /**
     * Impure: it may send a request, which it records in $sentRequest, and
     * it writes the cache.
     *
     * @phpstan-impure
     */
    protected function enrichIp(string $ip): array
    {
        $cacheKey = "threat_ip_geo:{$ip}";

        // Only an answer is remembered. A failed lookup comes back with every
        // field null, and Cache::remember() stored that like a result for
        // seven days — so after "fix the provider and run it again", the
        // rerun read the cached failures and asked nobody. A null entry left
        // by an earlier version counts as a miss for the same reason.
        $cached = Cache::get($cacheKey);

        if (is_array($cached) && ($cached['country_code'] ?? null) !== null) {
            return $cached;
        }

        $geo = $this->fetchGeoData($ip);
        $cloudProvider = $this->detectCloudProvider($ip, $geo['isp'] ?? null, $geo['org'] ?? null);

        $homeCountry = config('threat-detection.home_country', 'IN');
        $countryCode = $geo['country_code'] ?? null;

        $data = [
            'country_code' => $countryCode,
            'country_name' => $geo['country_name'] ?? null,
            'city' => $geo['city'] ?? null,
            'isp' => $geo['isp'] ?? null,
            'cloud_provider' => $cloudProvider,
            // Only flag as foreign when the country is known AND differs from
            // home. Unknown geo (failed lookup, private IP) is not "foreign".
            'is_foreign' => $countryCode !== null && $countryCode !== $homeCountry,
            'is_cloud_ip' => $cloudProvider !== null,
        ];

        if ($countryCode !== null) {
            Cache::put($cacheKey, $data, now()->addDays(7));
        }

        return $data;
    }

    /**
     * Whether this address is worth asking the provider about.
     *
     * A malformed value would be an SSRF primitive in the request URL; a
     * private or reserved one cannot be resolved and would spend a
     * rate-limited request to learn nothing.
     *
     * Shared with handle() so the run can tell a *skipped* address from an
     * *attempted and failed* one. Counting a deliberately skipped private
     * address as a failure would report an error on a healthy install whose
     * only traffic came from the local network.
     */
    protected function isLookupCandidate(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false
            && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    /**
     * A provider field as a string of at most $maxLength characters, or null.
     *
     * Anything that is not a scalar is dropped: the shipped provider returns
     * strings, and an array or object means something else is answering.
     */
    protected function boundedString(mixed $value, int $maxLength): ?string
    {
        if ($value === null || is_array($value) || is_object($value)) {
            return null;
        }

        $value = trim((string) $value);

        if ($value === '') {
            return null;
        }

        return mb_substr($value, 0, $maxLength);
    }

    protected function fetchGeoData(string $ip): array
    {
        try {
            if (!$this->isLookupCandidate($ip)) {
                return [];
            }

            $this->sentRequest = true;
            $response = Http::timeout(3)->get(
                rtrim($this->endpoint(), '/') . "/{$ip}?fields=countryCode,country,city,isp,org"
            );

            if ($response->successful()) {
                $data = $response->json();

                /*
                 * TD-012. The answer is written into fixed-width columns, and
                 * it comes from a third party over the network — so it is
                 * bounded and coerced here rather than trusted.
                 *
                 * Untrimmed, an over-long value raises on MySQL in strict
                 * mode, and the update that writes it sits outside this
                 * method's best-effort catch: the command would abort part-way
                 * through its loop and leave enrichment half applied. A value
                 * that fits can never do that.
                 *
                 * A non-scalar field is discarded rather than cast, since an
                 * array or object here means the provider is not returning what
                 * this code was written against and guessing would store
                 * nonsense.
                 */
                return [
                    'country_code' => $this->boundedString($data['countryCode'] ?? null, 5),
                    'country_name' => $this->boundedString($data['country'] ?? null, 100),
                    'city' => $this->boundedString($data['city'] ?? null, 100),
                    'isp' => $this->boundedString($data['isp'] ?? null, 255),
                    'org' => $this->boundedString($data['org'] ?? null, 255),
                ];
            }
        } catch (\Throwable $e) {
            // Geo lookup is best-effort
        }

        return [];
    }

    protected function detectCloudProvider(string $ip, ?string $isp = null, ?string $org = null): ?string
    {
        $searchText = strtolower(($isp ?? '') . ' ' . ($org ?? ''));
        foreach ($this->cloudIspKeywords as $keyword => $provider) {
            if (str_contains($searchText, strtolower($keyword))) {
                return $provider;
            }
        }

        foreach ($this->cloudPrefixes as $provider => $prefixes) {
            foreach ($prefixes as $prefix) {
                if (str_starts_with($ip, $prefix)) {
                    return $provider;
                }
            }
        }

        return null;
    }
}
