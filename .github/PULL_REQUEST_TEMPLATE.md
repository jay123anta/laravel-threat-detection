## What this changes

<!-- One or two sentences. -->

## Why

<!-- The problem it solves. Link an issue if there is one. -->

## Checklist

- [ ] `composer check` passes (lint, static analysis, tests)
- [ ] Added or updated tests
- [ ] Detection stays passive — no request is blocked, filtered or modified

### If this adds or changes a detection pattern

- [ ] Full-cycle test: HTTP request → middleware → assert on `threat_logs`
- [ ] A test proving what it does **not** match (false-positive guard)
- [ ] Sensitive matches added to `redact.labels`
- [ ] CHANGELOG entry under Unreleased
