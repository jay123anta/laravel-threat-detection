# Contributing

Thanks for helping. This is a security package, so a few things matter more
here than in a typical library — they're all listed below.

## Getting set up

```bash
git clone https://github.com/jay123anta/laravel-threat-detection
cd laravel-threat-detection
composer install
composer test
```

You need PHP 8.2+. The suite runs against Laravel 10 through 13 in CI; locally
you get whichever version composer resolves.

## Before you open a pull request

```bash
composer check     # runs lint, static analysis and tests
```

Or individually:

| Command | What it does |
|---|---|
| `composer test` | PHPUnit, 335 tests |
| `composer lint` | Pint style check (no changes written) |
| `composer format` | Pint, writes fixes |
| `composer analyse` | PHPStan level 5 |

CI runs all three. `phpstan-baseline.neon` holds pre-existing findings — please
don't regenerate it to silence a new error. Fix the error, or say in the PR why
it belongs in the baseline.

## Things specific to this package

**Detection must stay passive.** The middleware never blocks, filters or
modifies a request, and it swallows its own exceptions so a detection bug can
never take someone's site down. A PR that can abort a request won't be merged —
expose the decision instead, the way `isBlocklisted()` does, and let the
operator enforce it.

**A new pattern needs a full-cycle test.** Not a regex assertion — an HTTP
request through the middleware, asserting on what lands in `threat_logs`. Unit
asserts have repeatedly passed while the same pattern failed on a real request,
because the pre-screen or category gate dropped it first. See
`tests/Feature/DetectionGapRegressionTest.php`.

**Prove the false-positive side too.** Any new pattern should come with a test
showing what it does *not* match. The costliest bugs in this package's history
were patterns firing on ordinary traffic — a Chrome user-agent read as SSRF,
timestamps read as PII.

**Don't store what you detect.** If a pattern matches something sensitive, add
its label to `redact.labels` so the value is masked before it's written.

## Style

Pint with the `laravel` preset. Test methods are `snake_case` and read as
sentences (`detected_pii_is_not_written_to_the_payload`).

## Reporting a vulnerability

Don't open an issue — see [SECURITY.md](SECURITY.md).

## Why `illuminate/foundation` isn't in `composer.json`

The package uses foundation-provided helpers (`config()`, `response()`,
`abort()`, `dispatch()`) and `Illuminate\Foundation\Events\Dispatchable`, so
you'd expect it in `require`. It can't be: Laravel stopped publishing that
read-only split, and Packagist has nothing above `v1.1.2` for it, so
`illuminate/foundation: ^10.0` is unsatisfiable.

In practice every consumer has `laravel/framework`, which `replace`s all
`illuminate/*` splits and provides foundation. Please don't "fix" this by
adding the constraint — it will fail to resolve. If a granular-split consumer
ever appears, the fix is to stop using foundation helpers, not to declare them.
