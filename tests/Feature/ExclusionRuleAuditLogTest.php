<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use JayAnta\ThreatDetection\Services\ExclusionRuleService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Deleting an exclusion rule switches a detection back on, and the log line it
 * writes is the only record of what was switched back on.
 *
 * It wrote `path_pattern ?? '*'` — so a rule built from a site-root row, whose
 * path is empty or null, was recorded as covering every path, although the
 * matcher treats it as covering the root alone. The line now states the scope
 * the matcher actually applied.
 */
class ExclusionRuleAuditLogTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        config(['cache.default' => 'array']);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    public static function rules(): array
    {
        return [
            'from a root row, stored by an earlier version' => [7, null, 'exact path: /'],
            'from a root row' => [7, '', 'exact path: /'],
            'from an ordinary row' => [7, 'api/search', 'exact path: /api/search'],
            'written by hand, no path' => [null, null, 'every path'],
            'written by hand, a glob' => [null, 'admin/*', 'glob: admin/*'],
        ];
    }

    #[Test]
    #[DataProvider('rules')]
    public function the_log_states_the_scope_the_matcher_applied(?int $fromThreat, ?string $path, string $expected): void
    {
        $id = DB::table('threat_exclusion_rules')->insertGetId([
            'pattern_label' => 'SQL Injection UNION',
            'path_pattern' => $path,
            'created_from_threat_id' => $fromThreat,
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        Log::spy();

        $this->assertTrue((new ExclusionRuleService)->delete($id));

        Log::shouldHaveReceived('info')
            ->withArgs(fn (string $message, array $context = []) => $message === 'Threat exclusion rule deleted'
                && ($context['scope'] ?? null) === $expected)
            ->once();
    }
}
