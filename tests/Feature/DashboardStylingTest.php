<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The dashboard's styles ship with the package, compiled, instead of being
 * generated in the browser by Tailwind's CDN script.
 *
 * That script was pinned with an integrity hash, and an integrity hash makes
 * the browser fetch with CORS. cdn.tailwindcss.com sends no
 * Access-Control-Allow-Origin header, so every browser refused the script and
 * the dashboard rendered unstyled. Dropping the hash would have run
 * unverified third-party code on the page that shows an administrator this
 * application's security data.
 *
 * Compiled styles have no compiler at runtime, so a class added to a view
 * without rebuilding the stylesheet would silently render unstyled. The last
 * test fails when that happens; resources/views/layouts/styles.css says how
 * to rebuild.
 */
class DashboardStylingTest extends TestCase
{
    private const VIEWS = __DIR__ . '/../../resources/views';

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('threat-detection.dashboard.enabled', true);
        $app['config']->set('threat-detection.dashboard.guard', 'none');
        $app['config']->set('threat-detection.dashboard.middleware', ['web']);
        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
    }

    #[Test]
    public function the_dashboard_arrives_with_its_styles(): void
    {
        $response = $this->get('/threat-detection');
        $response->assertOk();
        $html = (string) $response->getContent();

        $this->assertMatchesRegularExpression('/<style>[^<]*\.bg-gray-900\{/', $html, 'the compiled styles are not in the page');

        // Preflight, the reset the CDN script used to inject, is part of it.
        $this->assertMatchesRegularExpression('/<style>[^<]*box-sizing:border-box/', $html);

        // Styles are inlined as text. Blade must not have compiled them.
        $this->assertStringContainsString('@media', $html);
    }

    /**
     * A script loaded with an integrity hash is fetched with CORS, so it only
     * runs if its host answers with Access-Control-Allow-Origin. jsDelivr
     * does; cdn.tailwindcss.com does not.
     */
    #[Test]
    public function every_script_comes_from_a_host_that_permits_integrity_checks(): void
    {
        $layout = file_get_contents(self::VIEWS . '/layouts/app.blade.php');

        preg_match_all('/<script[^>]*\ssrc="([^"]+)"/i', $layout, $sources);

        $this->assertNotEmpty($sources[1]);

        foreach ($sources[1] as $src) {
            $this->assertSame('cdn.jsdelivr.net', parse_url($src, PHP_URL_HOST), "{$src} cannot pass an integrity check");
        }
    }

    #[Test]
    public function every_class_the_views_use_has_a_compiled_rule(): void
    {
        $css = file_get_contents(self::VIEWS . '/layouts/styles.css');
        $classes = [];

        foreach (glob(self::VIEWS . '/{,*/}*.blade.php', GLOB_BRACE) as $view) {
            $source = file_get_contents($view);

            // Static class attributes are class lists in full.
            preg_match_all('/\sclass="([^"]*)"/', $source, $static);

            // Alpine bindings: the string literals are the classes, except the
            // ones compared against, e.g. in
            //   :class="family === 'llm_injection' ? 'text-pink-300' : ...".
            preg_match_all('/:class="([^"]*)"/', $source, $bound);
            preg_match_all("/(==\\s*)?'([^']*)'/", implode(' ', $bound[1]), $boundLiterals, PREG_SET_ORDER);
            $boundLists = array_column(array_filter($boundLiterals, fn (array $m) => $m[1] === ''), 2);

            // Class lists held in the component script, e.g. the badge maps and
            // the stat cards' colours: literals made only of utilities, at least
            // one of them a colour.
            preg_match_all("/'([a-z0-9:\\/. -]+)'/", $source, $scriptLiterals);
            $scriptLists = array_filter(
                $scriptLiterals[1],
                fn (string $literal) => preg_match('/(?:^|\s)[a-z:]*[a-z]+-[a-z]+-\d{2,3}(?:\/\d+)?(?:\s|$)/', $literal)
            );

            foreach ([...$static[1], ...$boundLists, ...$scriptLists] as $list) {
                foreach (preg_split('/\s+/', trim($list), -1, PREG_SPLIT_NO_EMPTY) as $class) {
                    $classes[$class] = basename($view);
                }
            }
        }

        // Guards the extraction: these are used through each route above.
        foreach (['bg-gray-900', 'hover:bg-gray-600', 'bg-green-900/30', 'text-purple-400', 'bg-orange-500/20'] as $known) {
            $this->assertArrayHasKey($known, $classes, "the extraction missed {$known}");
        }

        $missing = [];

        foreach ($classes as $class => $view) {
            $selector = '.' . preg_replace('/([:\/.\[\]%#])/', '\\\\$1', $class);

            if (!preg_match('/' . preg_quote($selector, '/') . '(?![\w-])/', $css)) {
                $missing[] = "{$class} ({$view})";
            }
        }

        $this->assertSame([], $missing, 'No compiled rule for these classes; rebuild resources/views/layouts/styles.css');
    }
}
