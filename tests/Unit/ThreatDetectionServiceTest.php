<?php

namespace JayAnta\ThreatDetection\Tests\Unit;

use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use PHPUnit\Framework\Attributes\Test;
use JayAnta\ThreatDetection\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class ThreatDetectionServiceTest extends TestCase
{
    private ThreatDetectionService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new ThreatDetectionService();
    }

    #[Test]
    public function it_returns_non_empty_default_patterns(): void
    {
        $patterns = $this->service->getDefaultThreatPatterns();

        $this->assertIsArray($patterns);
        $this->assertNotEmpty($patterns);

        foreach ($patterns as $regex => $label) {
            $this->assertIsString($regex);
            $this->assertIsString($label);
            $this->assertStringStartsWith('/', $regex);
        }
    }

    #[Test]
    public function it_detects_sql_injection(): void
    {
        $payload = "QUERY: {\"q\":\"' UNION SELECT * FROM users--\"}";
        $results = $this->service->detectThreatPatterns($payload);

        $labels = array_column($results, 0);
        $this->assertNotEmpty($results);
        $this->assertTrue(
            in_array('SQL Injection UNION', $labels) || in_array('SQL SELECT Query', $labels),
            'Expected SQL injection to be detected'
        );
    }

    #[Test]
    public function it_detects_xss_script_tag(): void
    {
        $payload = "BODY: {\"msg\":\"<script>alert(1)</script>\"}";
        $results = $this->service->detectThreatPatterns($payload);

        $labels = array_column($results, 0);
        $this->assertNotEmpty($results);
        $this->assertContains('XSS Script Tag', $labels);
    }

    #[Test]
    public function it_detects_directory_traversal(): void
    {
        $payload = "QUERY: {\"file\":\"../../etc/passwd\"}";
        $results = $this->service->detectThreatPatterns($payload);

        $labels = array_column($results, 0);
        $this->assertNotEmpty($results);
        $this->assertContains('Directory Traversal', $labels);
    }

    #[Test]
    public function it_detects_rce_shell_functions(): void
    {
        $payload = "BODY: {\"cmd\":\"system('ls -la')\"}";
        $results = $this->service->detectThreatPatterns($payload);

        $labels = array_column($results, 0);
        $this->assertNotEmpty($results);
        $this->assertContains('RCE Shell Function', $labels);
    }

    #[Test]
    public function it_returns_empty_for_normal_text(): void
    {
        $payload = "QUERY: {\"search\":\"latest news\",\"page\":\"1\"}";
        $results = $this->service->detectThreatPatterns($payload);

        $this->assertEmpty($results, 'Normal text should not trigger any threat patterns');
    }

    #[Test]
    public function each_result_has_correct_structure(): void
    {
        $payload = "BODY: {\"q\":\"<script>alert('xss')</script>\"}";
        $results = $this->service->detectThreatPatterns($payload, 'test-source');

        foreach ($results as $result) {
            $this->assertIsArray($result);
            $this->assertCount(3, $result);
            [$label, $level, $source] = $result;
            $this->assertIsString($label);
            $this->assertContains($level, ['high', 'medium', 'low']);
            $this->assertIsString($source);
        }
    }

    #[Test]
    public function it_suppresses_auth_patterns_on_auth_paths(): void
    {
        $payload = "BODY: password=mysecretpassword123";

        $withAuth = $this->service->detectThreatPatterns($payload, 'middleware', true);
        $withoutAuth = $this->service->detectThreatPatterns($payload, 'middleware', false);

        $authLabels = array_column($withAuth, 0);
        $nonAuthLabels = array_column($withoutAuth, 0);

        $this->assertNotContains('Password Exposure', $authLabels);
        $this->assertContains('Password Exposure', $nonAuthLabels);
    }

    #[Test]
    public function it_logs_ddos_when_threshold_exceeded(): void
    {
        $this->createThreatLogsTable();

        // Set a low threshold for testing
        config(['threat-detection.ddos.threshold' => 3]);
        config(['threat-detection.ddos.window' => 60]);

        $service = new ThreatDetectionService();

        // Pre-fill cache to simulate requests just below threshold
        Cache::put('ddos:10.0.0.1', 3, now()->addSeconds(60));

        // Next request should exceed threshold and log DDoS
        $request = Request::create('/test', 'GET');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');

        $service->detectAndLogFromRequest($request);

        $this->assertDatabaseHas('threat_logs', [
            'ip_address' => '10.0.0.1',
            'type' => '[ddos] Excessive Requests',
            'threat_level' => 'high',
        ]);
    }

    // ── Evasion Resistance Tests ──

    #[Test]
    public function it_detects_sql_comment_evasion(): void
    {
        $segments = ['query' => 'UNION/**/SELECT'];
        $matches = $this->service->detectThreatPatternsWithContext($segments);

        $labels = array_column($matches, 'label');
        $this->assertContains('SQL Comment Evasion', $labels);
    }

    #[Test]
    public function it_detects_sql_char_encoding(): void
    {
        $segments = ['query' => "CHAR(39)"];
        $matches = $this->service->detectThreatPatternsWithContext($segments);

        $labels = array_column($matches, 'label');
        $this->assertContains('SQL Injection CHAR Encoding', $labels);
    }

    #[Test]
    public function it_detects_double_url_encoding(): void
    {
        $segments = ['query' => '%2527'];
        $matches = $this->service->detectThreatPatternsWithContext($segments);

        $labels = array_column($matches, 'label');
        $this->assertContains('Double URL Encoding', $labels);
    }

    #[Test]
    public function it_catches_obfuscated_sql_after_normalization(): void
    {
        $segments = ['query' => 'UNION/**/SELECT'];
        $matches = $this->service->detectThreatPatternsWithContext($segments);

        $labels = array_column($matches, 'label');
        // Normalization strips /**/ → "UNION SELECT" which triggers the SQL pattern
        $this->assertContains('SQL Injection UNION', $labels);
    }

    #[Test]
    public function it_does_not_false_positive_on_double_dash(): void
    {
        $segments = ['body' => 'font--bold'];
        $matches = $this->service->detectThreatPatternsWithContext($segments);

        $labels = array_column($matches, 'label');
        $this->assertNotContains('SQL Comment Syntax', $labels);

        $segments2 = ['query' => '--verbose'];
        $matches2 = $this->service->detectThreatPatternsWithContext($segments2);

        $labels2 = array_column($matches2, 'label');
        $this->assertNotContains('SQL Comment Syntax', $labels2);
    }
}
