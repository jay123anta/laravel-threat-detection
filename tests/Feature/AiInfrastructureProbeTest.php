<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ProbeDetectorService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The AI-infrastructure probe pack (1.9.0).
 *
 * Self-hosted LLM gateways are a routine scanning target. The paths in the
 * pack are the ones attackers were measured hitting — Ollure, a honeypot
 * emulating the Ollama API, recorded 290,887 interactions from 2,793 unique
 * IPs over 84 days (arXiv:2609.29757) — rather than the ones that seemed
 * likely.
 *
 * Two properties matter more than the path list itself:
 *
 *   1. It is OFF by default. An install that does not opt in reports exactly
 *      what 1.8.0 reported. Most of this file exists to prove that.
 *   2. An operator's own `paths` entry beats the pack, so turning the pack on
 *      cannot silently reclassify a path they have already labelled.
 */
class AiInfrastructureProbeTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
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
            'threat-detection.probe_tracking.enabled' => true,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->group(function () {
            foreach ([
                '/v1/models', '/api/tags', '/api/pull', '/mcp', '/.cursor/rules',
                '/api/v1/validate/code', '/wp-admin', '/harmless-page',
            ] as $path) {
                Route::get($path, fn () => response('OK', 200));
            }
        });
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    /** Turning the pack on mid-test must invalidate the memoised path index. */
    private function enablePack(array $overrides = []): void
    {
        config(['threat-detection.probe_tracking.ai_infrastructure.enabled' => true] + $overrides);
        ProbeDetectorService::flushCaches();
    }

    /** @return array<int, array{type: string, threat_level: string}> */
    private function probeRows(): array
    {
        return DB::table('threat_logs')
            ->where('type', 'like', '[probe]%')
            ->get(['type', 'threat_level'])
            ->map(fn ($r) => ['type' => $r->type, 'threat_level' => $r->threat_level])
            ->all();
    }

    // ── off by default ─────────────────────────────────────────────────────

    /**
     * @return array<string, array{0: string}>
     */
    public static function packPaths(): array
    {
        return [
            'ollama enumeration' => ['/api/tags'],
            'openai-compatible' => ['/v1/models'],
            'mcp server' => ['/mcp'],
            'agent rules file' => ['/.cursor/rules'],
            'langflow cve path' => ['/api/v1/validate/code'],
        ];
    }

    #[Test]
    #[DataProvider('packPaths')]
    public function a_pack_path_is_not_reported_until_the_pack_is_turned_on(string $path): void
    {
        $this->get($path)->assertStatus(200);

        $this->assertSame(
            [],
            $this->probeRows(),
            "{$path} was reported as a probe with the pack off — an existing install's output would change on upgrade"
        );
    }

    /**
     * The positive control for every test above: with the pack off the probe
     * layer is still working, so "nothing logged" means the pack is off rather
     * than probe tracking being broken.
     */
    #[Test]
    public function the_existing_probe_paths_still_report_with_the_pack_off(): void
    {
        $this->get('/wp-admin')->assertStatus(200);

        $this->assertSame(
            [['type' => '[probe] WordPress Admin', 'threat_level' => 'medium']],
            $this->probeRows()
        );
    }

    // ── on when asked ──────────────────────────────────────────────────────

    #[Test]
    #[DataProvider('packPaths')]
    public function a_pack_path_is_reported_once_the_pack_is_turned_on(string $path): void
    {
        $this->enablePack();

        $this->get($path)->assertStatus(200);

        $rows = $this->probeRows();
        $this->assertCount(1, $rows, "{$path} produced " . count($rows) . ' probe rows');
        $this->assertStringStartsWith('[probe] ', $rows[0]['type']);
    }

    /**
     * The pack ships at high severity rather than the general probe default:
     * these paths exist on almost no public app, so a request for one is a
     * deliberate hunt rather than broad spraying.
     */
    #[Test]
    public function pack_paths_are_high_severity_while_the_general_default_stays_medium(): void
    {
        $this->enablePack();

        $this->get('/v1/models')->assertStatus(200);
        $this->get('/wp-admin')->assertStatus(200);

        $levels = [];
        foreach ($this->probeRows() as $row) {
            $levels[$row['type']] = $row['threat_level'];
        }

        $this->assertSame('high', $levels['[probe] OpenAI-Compatible Model Enumeration'] ?? null);
        $this->assertSame('medium', $levels['[probe] WordPress Admin'] ?? null, 'the pack changed the level of an unrelated path');
    }

    #[Test]
    public function turning_the_pack_on_does_not_disturb_the_existing_paths(): void
    {
        $this->enablePack();

        $this->get('/wp-admin')->assertStatus(200);

        $this->assertSame(
            [['type' => '[probe] WordPress Admin', 'threat_level' => 'medium']],
            $this->probeRows()
        );
    }

    #[Test]
    public function an_ordinary_page_is_not_a_probe_with_the_pack_on(): void
    {
        $this->enablePack();

        $this->get('/harmless-page')->assertStatus(200);

        $this->assertSame([], $this->probeRows());
    }

    // ── the operator's own list wins ───────────────────────────────────────

    /**
     * An app that legitimately serves an LLM API has its own opinion about
     * /v1/models. Turning the pack on must not overrule it.
     */
    #[Test]
    public function an_operator_entry_for_the_same_path_beats_the_pack(): void
    {
        config(['threat-detection.probe_tracking.paths' => [
            '/v1/models' => ['label' => 'Our Own Model Index', 'level' => 'low'],
        ]]);
        $this->enablePack();

        $this->get('/v1/models')->assertStatus(200);

        $this->assertSame(
            [['type' => '[probe] Our Own Model Index', 'threat_level' => 'low']],
            $this->probeRows()
        );
    }

    // ── the definition format ──────────────────────────────────────────────

    /**
     * The string form has shipped since 1.3.0 and must keep working
     * unchanged, taking its level from default_level.
     */
    #[Test]
    public function a_plain_string_definition_still_works_and_uses_the_default_level(): void
    {
        config([
            'threat-detection.probe_tracking.default_level' => 'low',
            'threat-detection.probe_tracking.paths' => ['/harmless-page' => 'Custom String Probe'],
        ]);
        ProbeDetectorService::flushCaches();

        $this->get('/harmless-page')->assertStatus(200);

        $this->assertSame(
            [['type' => '[probe] Custom String Probe', 'threat_level' => 'low']],
            $this->probeRows()
        );
    }

    #[Test]
    public function a_per_path_level_overrides_the_default_for_that_path_only(): void
    {
        config([
            'threat-detection.probe_tracking.default_level' => 'low',
            'threat-detection.probe_tracking.paths' => [
                '/harmless-page' => ['label' => 'Loud Probe', 'level' => 'high'],
                '/wp-admin' => 'Quiet Probe',
            ],
        ]);
        ProbeDetectorService::flushCaches();

        $this->get('/harmless-page')->assertStatus(200);
        $this->get('/wp-admin')->assertStatus(200);

        $levels = [];
        foreach ($this->probeRows() as $row) {
            $levels[$row['type']] = $row['threat_level'];
        }

        $this->assertSame('high', $levels['[probe] Loud Probe'] ?? null);
        $this->assertSame('low', $levels['[probe] Quiet Probe'] ?? null);
    }

    /**
     * A malformed entry must be skipped rather than logged as a probe with an
     * empty label or taken as a fatal — config is operator-editable.
     *
     * @return array<string, array{0: mixed}>
     */
    public static function malformedDefinitions(): array
    {
        return [
            'empty string' => [''],
            'whitespace only' => ['   '],
            'array with no label' => [['level' => 'high']],
            'array with empty label' => [['label' => '', 'level' => 'high']],
            'null' => [null],
            'integer' => [42],
        ];
    }

    #[Test]
    #[DataProvider('malformedDefinitions')]
    public function a_malformed_path_definition_is_skipped_rather_than_reported(mixed $definition): void
    {
        // A valid entry sits beside the broken one. Asserting only "nothing
        // reported" would pass just as happily if the malformed entry threw
        // and the middleware's catch swallowed it — the request would still
        // be 200 and the table still empty. The valid entry is what separates
        // "skipped cleanly" from "blew up on the way past".
        config(['threat-detection.probe_tracking.paths' => [
            '/harmless-page' => $definition,
            '/wp-admin' => 'Still Working',
        ]]);
        ProbeDetectorService::flushCaches();

        Log::spy();

        $this->get('/harmless-page')->assertStatus(200);
        $this->assertSame([], $this->probeRows(), 'a malformed definition was reported as a probe');

        $this->get('/wp-admin')->assertStatus(200);
        $this->assertSame(
            [['type' => '[probe] Still Working', 'threat_level' => 'medium']],
            $this->probeRows(),
            'a malformed entry poisoned the path index for every other path'
        );

        Log::shouldNotHaveReceived('error');
    }

    /**
     * The wildcard branch is where skipping a malformed entry actually earns
     * its keep. For an exact path a null entry is invisible anyway, because
     * isset() is false for null — so the guard is unobservable there, and a
     * test using only exact paths cannot tell whether it exists. A wildcard
     * that *matches* the request reaches the entry directly.
     */
    #[Test]
    public function a_malformed_wildcard_definition_is_skipped_rather_than_matched(): void
    {
        config(['threat-detection.probe_tracking.paths' => [
            '/harmless-*' => ['level' => 'high'],   // no label
            '/wp-admin' => 'Still Working',
        ]]);
        ProbeDetectorService::flushCaches();

        Log::spy();

        $this->get('/harmless-page')->assertStatus(200);
        $this->assertSame(
            [],
            $this->probeRows(),
            'a wildcard entry with no label produced a probe row with an empty label'
        );

        $this->get('/wp-admin')->assertStatus(200);
        $this->assertSame(
            [['type' => '[probe] Still Working', 'threat_level' => 'medium']],
            $this->probeRows()
        );

        Log::shouldNotHaveReceived('error');
    }

    /**
     * Wildcards carry their level too — the pack uses them for /mcp/* and the
     * agent-config directories.
     */
    #[Test]
    public function a_wildcard_pack_path_reports_at_the_pack_level(): void
    {
        $this->enablePack();

        Route::middleware('threat-detect')->get('/mcp/tools/list', fn () => response('OK', 200));

        $this->get('/mcp/tools/list')->assertStatus(200);

        $rows = $this->probeRows();
        $this->assertCount(1, $rows);
        $this->assertSame('high', $rows[0]['threat_level']);
    }
}
