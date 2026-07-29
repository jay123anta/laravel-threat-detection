<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Cache;

/**
 * Phase 1 v1.3.0: Full-cycle tests for new security patterns.
 *
 * Tests CRLF injection, null byte, Shellshock, Spring4Shell, Windows command
 * injection, SVG XSS, SQL DDL/DML, Java deserialization, expanded SSTI,
 * open redirect, and normalization pipeline expansion.
 *
 * Each test sends a real HTTP request through the threat-detect middleware,
 * writes to the database, and asserts on the actual rows.
 */
class Phase1SecurityPatternsTest extends TestCase
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
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->group(function () {
            Route::get('/phase1-test', fn() => response('OK', 200));
            Route::post('/phase1-test', fn() => response('OK', 200));
        });
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    // ────────────────────────────────────────────
    //  CRLF Injection (CRS 921, CWE-113)
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_crlf_injection_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => "value%0d%0aSet-Cookie: hacked=true"]);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] CRLF Injection',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_lf_injection_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => "header%0aX-Injected: yes"]);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] LF Injection',
        ]);
    }

    // ────────────────────────────────────────────
    //  Null Byte Injection (CWE-626)
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_null_byte_injection_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['file' => "image.php%00.jpg"]);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Null Byte Injection',
            'threat_level' => 'high',
        ]);
    }

    // ────────────────────────────────────────────
    //  Shellshock (CVE-2014-6271)
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_shellshock_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['cmd' => "() { :;}; /bin/bash -c 'cat /etc/passwd'"]);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Shellshock CVE-2014-6271',
            'threat_level' => 'high',
        ]);
    }

    // ────────────────────────────────────────────
    //  Spring4Shell (CVE-2022-22965)
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_spring4shell_is_detected(): void
    {
        // PHP converts dots to underscores in query param names, so use POST body
        $this->call('POST', '/phase1-test', ['payload' => 'class.module.classLoader.resources.context.parent']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Spring4Shell CVE-2022-22965',
            'threat_level' => 'high',
        ]);
    }

    // ────────────────────────────────────────────
    //  Windows Command Injection (CRS 932)
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_windows_cmd_execution_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => 'cmd /c dir C:\\Windows\\System32']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Windows CMD Execution',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_powershell_execution_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => 'powershell -ExecutionPolicy Bypass -File exploit.ps1']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] PowerShell Execution',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_windows_script_host_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => 'wscript C:\\malware.vbs']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Windows Script Host',
        ]);
    }

    #[Test]
    public function full_cycle_windows_net_command_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => 'net user administrator password123']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Windows Net Command',
        ]);
    }

    // ────────────────────────────────────────────
    //  SVG/HTML Event Handler XSS (CRS 941)
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_svg_xss_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => '<svg onload=alert(1)>']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] XSS SVG Event Handler',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_body_onload_xss_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => '<body onload=alert(document.cookie)>']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] XSS HTML Event Handler',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_img_onerror_xss_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => '<img src=x onerror=alert(1)>']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] XSS HTML Event Handler',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_css_expression_xss_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => '<div style="width: expression(alert(1))">']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] XSS CSS Expression',
            'threat_level' => 'high',
        ]);
    }

    // ────────────────────────────────────────────
    //  SQL DDL/DML Injection (CRS 942)
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_sql_drop_table_is_detected(): void
    {
        $this->get('/phase1-test?q=DROP TABLE users');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL DDL Injection',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_sql_insert_into_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['q' => "INSERT INTO users VALUES(1,'admin','pass')"]);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL DML Injection',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_sql_into_outfile_is_detected(): void
    {
        $this->get('/phase1-test?q=SELECT+*+INTO+OUTFILE+"/tmp/data.csv"+FROM+users');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL File Write',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_sql_load_file_is_detected(): void
    {
        $this->get('/phase1-test?q=SELECT+LOAD_FILE("/etc/passwd")');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL File Read',
            'threat_level' => 'high',
        ]);
    }

    // ────────────────────────────────────────────
    //  Java Deserialization (CWE-502)
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_java_deserialization_base64_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['data' => 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1h']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Java Deserialization',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_java_serialization_hex_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['data' => 'aced00057372001173756e2e7265666c6563742e']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Java Serialization Magic Bytes',
            'threat_level' => 'high',
        ]);
    }

    // ────────────────────────────────────────────
    //  Expanded SSTI (CRS 944)
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_ssti_mathematical_probe_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => '{{7*7}}']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SSTI Mathematical Probe',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_ssti_config_access_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => '{{config.items()}}']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SSTI Config Access',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_ssti_jinja2_import_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => '{% import "os" %}']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SSTI Jinja2 Import',
            'threat_level' => 'high',
        ]);
    }

    // ────────────────────────────────────────────
    //  Open Redirect (CWE-601)
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_open_redirect_is_detected(): void
    {
        $this->get('/phase1-test?redirect=https://evil.com/phish');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Open Redirect',
            'threat_level' => 'medium',
        ]);
    }

    #[Test]
    public function full_cycle_open_redirect_next_param_is_detected(): void
    {
        $this->get('/phase1-test?next=http://attacker.com/steal');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Open Redirect',
            'threat_level' => 'medium',
        ]);
    }

    // ────────────────────────────────────────────
    //  Normalization Pipeline Expansion
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_html_entity_encoded_xss_is_detected_after_normalization(): void
    {
        // &#60;script&#62; should be normalized to <script> and caught
        $this->call('POST', '/phase1-test', ['input' => '&#60;script&#62;alert(1)&#60;/script&#62;']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] XSS Script Tag',
        ]);
    }

    #[Test]
    public function full_cycle_html_entity_evasion_is_flagged_before_normalization(): void
    {
        $this->call('POST', '/phase1-test', ['input' => '&#60;script&#62;alert(1)']);

        // The evasion pattern itself should be caught
        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] HTML Entity Encoding Evasion',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_unicode_escape_evasion_is_detected(): void
    {
        $this->call('POST', '/phase1-test', ['input' => '\\u003cscript\\u003ealert(1)']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Unicode Escape Evasion',
            'threat_level' => 'high',
        ]);
    }

    // ────────────────────────────────────────────
    //  Cross-cutting: passive detector (never blocks)
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_all_new_patterns_never_block_request(): void
    {
        // Even the most dangerous payloads return 200
        $this->get('/phase1-test?q=DROP TABLE users')->assertStatus(200);
        $this->call('POST', '/phase1-test', ['cmd' => 'powershell -c whoami'])->assertStatus(200);
        $this->call('POST', '/phase1-test', ['x' => '<svg onload=alert(1)>'])->assertStatus(200);
        $this->call('POST', '/phase1-test', ['x' => '() { :;}; /bin/bash'])->assertStatus(200);
    }

    // ────────────────────────────────────────────
    //  False positive check: legitimate content
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_legitimate_redirect_param_without_url_not_flagged(): void
    {
        // "redirect=dashboard" should NOT trigger Open Redirect (no http://)
        $this->get('/phase1-test?redirect=dashboard');

        $this->assertDatabaseMissing('threat_logs', [
            'type' => '[middleware] Open Redirect',
        ]);
    }

    #[Test]
    public function full_cycle_normal_net_word_not_flagged_as_windows_command(): void
    {
        // "networking" should NOT trigger Windows Net Command
        $this->call('POST', '/phase1-test', ['description' => 'networking and internet services']);

        $this->assertDatabaseMissing('threat_logs', [
            'type' => '[middleware] Windows Net Command',
        ]);
    }

    #[Test]
    public function double_url_encoded_sql_injection_is_no_longer_missed(): void
    {
        // Fully char-encode the payload, then encode again. After Laravel's single
        // query decode it is still %55%4E%49... — no visible keyword, so the old
        // pre-screen skipped the whole segment. The normalizer recovers it; it must log.
        $clear  = 'UNION SELECT password FROM users';
        $single = implode('', array_map(fn($c) => '%' . strtoupper(bin2hex($c)), str_split($clear)));
        $double = str_replace('%', '%25', $single);

        $this->get('/phase1-test?q=' . $double);

        $this->assertGreaterThan(
            0,
            \DB::table('threat_logs')->count(),
            'A double-URL-encoded SQLi payload must be detected, not skipped by the pre-screen.'
        );
    }
}
