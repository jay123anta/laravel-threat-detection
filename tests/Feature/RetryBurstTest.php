<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ThreatCorrelationService;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Retry bursts: one actor, many different payloads of one attack class.
 *
 * The complement of a mutation chain, which is one payload in many
 * encodings. An attacker that writes a new payload each time — how an
 * LLM-driven exploitation agent iterates, converging in 10–40 generated
 * attempts (AWE, arXiv:2603.00960) — leaves a row of one-variant chains and
 * no chain at all. These tests pin both directions, so neither analysis can
 * quietly absorb the other.
 */
class RetryBurstTest extends TestCase
{
    private const SIGNALS = 'threat_actor_signals';

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config(['threat-detection.actor_signals.table' => self::SIGNALS]);
        (require __DIR__ . '/../../database/migrations/create_threat_actor_signals_table.php.stub')->up();

        config([
            'cache.default' => 'array',
            'threat-detection.enabled' => true,
            'threat-detection.detection_mode' => 'strict',
            'threat-detection.min_confidence' => 0,
            'threat-detection.skip_paths' => [],
            'threat-detection.only_paths' => [],
            'threat-detection.whitelisted_ips' => [],
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.content_paths' => [],
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'threat-detection.actor_signals.enabled' => true,
        ]);

        ThreatDetectionService::flushCaches();

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function send(string $payload): void
    {
        $this->get('/search?q=' . urlencode($payload))->assertStatus(200);
    }

    /** @return array<int, array<string, mixed>> */
    private function burstsFor(string $label): array
    {
        return array_values(array_filter(
            (new ThreatCorrelationService)->detectRetryBursts(60, 5),
            fn ($burst) => $burst['label'] === $label
        ));
    }

    #[Test]
    public function distinct_payloads_of_one_attack_are_a_burst_and_not_a_chain(): void
    {
        foreach (['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'] as $column) {
            $this->send("' UNION SELECT {$column} FROM users--");
        }

        $bursts = $this->burstsFor('SQL Injection UNION');

        $this->assertCount(1, $bursts, 'eight new payloads of one attack were not seen as a burst');
        $this->assertSame('127.0.0.1', $bursts[0]['actor_key']);
        $this->assertSame(8, $bursts[0]['payload_count']);

        $this->assertSame([], (new ThreatCorrelationService)->detectMutationChains(60, 5), 'distinct payloads were read as encodings of one');
    }

    /**
     * The count is of payloads, not of the encodings they arrived in. Six
     * payloads, one of them also sent re-encoded, is six — counting variants
     * would say seven and conflate the two analyses.
     */
    #[Test]
    public function a_re_encoded_payload_is_not_counted_twice(): void
    {
        foreach (['a', 'b', 'c', 'd', 'e', 'f'] as $column) {
            $this->send("' UNION SELECT {$column} FROM users--");
        }
        $this->send("' UNION/**/SELECT a FROM users--");

        $bursts = $this->burstsFor('SQL Injection UNION');

        $this->assertCount(1, $bursts);
        $this->assertSame(6, $bursts[0]['payload_count']);
    }

    #[Test]
    public function one_payload_in_many_encodings_is_a_chain_and_not_a_burst(): void
    {
        foreach ([
            "' UNION SELECT password FROM users--",
            "' UNION/**/SELECT password FROM users--",
            "' UNION%20SELECT password FROM users--",
            "' Union Select password From users--",
            "' UNION\tSELECT password FROM users--",
            "' UNION  SELECT  password  FROM  users--",
        ] as $payload) {
            $this->send($payload);
        }

        $this->assertNotEmpty((new ThreatCorrelationService)->detectMutationChains(60, 5), 'the chain itself was not seen, so this proves nothing');
        $this->assertSame([], $this->burstsFor('SQL Injection UNION'), 're-encodings of one payload were counted as new payloads');
    }

    #[Test]
    public function fewer_than_five_payloads_is_not_a_burst(): void
    {
        foreach (['a', 'b', 'c', 'd'] as $column) {
            $this->send("' UNION SELECT {$column} FROM users--");
        }

        $this->assertSame([], $this->burstsFor('SQL Injection UNION'));
    }

    #[Test]
    public function nothing_is_reported_without_actor_signals(): void
    {
        foreach (['a', 'b', 'c', 'd', 'e', 'f'] as $column) {
            $this->send("' UNION SELECT {$column} FROM users--");
        }

        config(['threat-detection.actor_signals.enabled' => false]);

        $this->assertSame([], (new ThreatCorrelationService)->detectRetryBursts(60, 5));
    }

    /** Reachable where an operator looks: the correlation API and the AI section. */
    #[Test]
    public function the_apis_report_retry_bursts(): void
    {
        foreach (['a', 'b', 'c', 'd', 'e', 'f'] as $column) {
            $this->send("' UNION SELECT {$column} FROM users--");
        }

        $correlation = $this->getJson('/api/threat-detection/correlation?type=retries')->assertStatus(200)->json('data.retry_bursts');
        $this->assertNotEmpty($correlation);

        $ai = $this->getJson('/api/threat-detection/ai-threats')->assertStatus(200)->json('data.retry_bursts');
        $this->assertNotEmpty($ai);
    }
}
