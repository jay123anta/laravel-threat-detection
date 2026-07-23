# Security Policy

`jayanta/laravel-threat-detection` is a security tool, so we take the security of
the package itself seriously. Thank you for helping keep it and its users safe.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.3.x   | :white_check_mark: |
| < 1.3   | :x:                |

Security fixes are applied to the latest 1.x release. Please upgrade to the most
recent version before reporting an issue.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Instead, report them privately using one of these channels:

- **Email:** jay123anta@gmail.com — put `SECURITY` in the subject line.
- **GitHub Security Advisories:** use the *"Report a vulnerability"* button under
  the repository's **Security** tab (preferred — it keeps the report private and
  lets us collaborate on a fix).

Please include, as far as you can:

- the affected version(s),
- a description of the issue and its impact,
- steps to reproduce (a minimal request/payload or failing test is ideal),
- and any suggested remediation.

## What to Expect

- We aim to **acknowledge** your report within **3 business days**.
- We will confirm the issue, keep you updated on progress, and let you know when
  a fix is released.
- We follow **coordinated disclosure**: please give us reasonable time to release
  a fix before any public disclosure. We're happy to credit you in the release
  notes and advisory unless you prefer to remain anonymous.

## Scope Notes

A few things specific to this package that are worth knowing before reporting:

- **It is a passive IDS.** By design the middleware only *logs* threats — it never
  blocks, rejects, or alters a request. "It didn't block an attack" is expected
  behaviour, not a vulnerability.
- **The dashboard and API expose sensitive data** (attacker IPs, payloads). They
  default to `guard = none` for a zero-config first run and log a daily warning.
  Leaving them unauthenticated in production is a misconfiguration to fix on your
  side (set `THREAT_DETECTION_DASHBOARD_GUARD` / `THREAT_DETECTION_API_GUARD`), not
  a package vulnerability — but if you find a way to *bypass* a configured guard,
  that absolutely is one, so please report it.
- Reports of detection **evasion** (a real attack pattern the engine misses) or
  **false positives** are very welcome — but those can go through normal public
  issues, since they aren't sensitive.
