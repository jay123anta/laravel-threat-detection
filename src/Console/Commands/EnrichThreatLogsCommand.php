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
     * The default is cleartext HTTP because ip-api.com's free tier answers 403
     * over HTTPS — switching the default to https:// would break enrichment for
     * every free-tier user, and silently, since a failed lookup is swallowed as
     * best-effort. Two things follow that operators should know: the attacking
     * IPs you look up are disclosed to a third party, and they travel
     * unencrypted, so an on-path observer can read them and forge the answers.
     *
     * Set THREAT_DETECTION_GEO_ENDPOINT to the HTTPS endpoint if you hold an
     * ip-api key, or to any other provider returning the same field names.
     * Enrichment is opt-in either way: nothing is sent unless you run this
     * command.
     */
    protected function endpoint(): string
    {
        return (string) config(
            'threat-detection.enrichment.endpoint',
            'http://ip-api.com/json'
        );
    }

    public function handle(): int
    {
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

        foreach ($ips as $ip) {
            $data = $this->enrichIp($ip);

            DB::table($table)
                ->where('ip_address', $ip)
                ->when(!$force, fn ($q) => $q->whereNull('country_code'))
                ->update($data);

            $bar->advance();
            usleep(1400000); // Rate limit: ~43 req/min (ip-api.com free tier allows 45/min)
        }

        $bar->finish();
        $this->newLine();
        $this->info('Enrichment complete!');

        return 0;
    }

    protected function enrichIp(string $ip): array
    {
        $cacheKey = "threat_ip_geo:{$ip}";

        return Cache::remember($cacheKey, now()->addDays(7), function () use ($ip) {
            $geo = $this->fetchGeoData($ip);
            $cloudProvider = $this->detectCloudProvider($ip, $geo['isp'] ?? null, $geo['org'] ?? null);

            $homeCountry = config('threat-detection.home_country', 'IN');
            $countryCode = $geo['country_code'] ?? null;

            return [
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
        });
    }

    protected function fetchGeoData(string $ip): array
    {
        try {
            // Validate IP format to prevent SSRF via crafted values
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return [];
            }

            // Skip private/reserved ranges — the geo API can't resolve them and
            // there's no point spending a rate-limited request (or flagging them).
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return [];
            }

            $response = Http::timeout(3)->get(
                rtrim($this->endpoint(), '/') . "/{$ip}?fields=countryCode,country,city,isp,org"
            );

            if ($response->successful()) {
                $data = $response->json();

                return [
                    'country_code' => $data['countryCode'] ?? null,
                    'country_name' => $data['country'] ?? null,
                    'city' => $data['city'] ?? null,
                    'isp' => $data['isp'] ?? null,
                    'org' => $data['org'] ?? null,
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
