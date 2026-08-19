# Upgrading

Only versions with required action are listed. Anything not mentioned upgraded
without changes.

---

## 1.6.x → 1.7.0

Three defaults changed and one behaviour tightened. Run this first — it reports
most of what follows:

```bash
composer update jayanta/laravel-threat-detection
php artisan threat-detection:doctor
```

### 1. Detected secrets are now redacted before storage

Values matched by a PII or credential pattern are masked in the stored payload
**and** URL. Previously a PAN, mobile number or password that tripped a pattern
was written to `threat_logs` verbatim.

Nothing to do unless you rely on full payloads for forensics:

```env
THREAT_DETECTION_REDACT=false
```

### 2. Disabling a detection now requires elevated access

`POST /threats/{id}/false-positive` and `DELETE /exclusion-rules/{id}` are
checked against a new `api.write_guard`, defaulting to `role`. Reading the log
and the dashboard are unaffected.

**If your user model has no `hasRole()`, the false-positive button will 403.**

```env
THREAT_DETECTION_API_WRITE_GUARD=auth   # or: none, to restore 1.6.x behaviour
```

### 3. Exclusion rules match labels exactly

A rule with `pattern_label` of `SQL` previously disabled every SQL pattern by
substring match. Matching is now exact.

Rules created through the dashboard's false-positive button always stored exact
labels and are unaffected. **Hand-inserted rows relying on partial matches will
stop excluding** — they fail toward re-enabling detection, so check
`threat_exclusion_rules` if you wrote any by hand.

### 4. Expect more entries, not fewer

Several patterns that never fired now do — the request path is scanned, custom
patterns no longer need an unrelated keyword present, and cloud-metadata SSRF is
detected regardless of field name.

If your app serves a bare `/admin`, `/test`, `/debug`, `/console`, `/backup` or
`/internal` route, each now logs a low-severity entry per IP every 5 minutes.
**Delete the pattern from your published `custom_patterns`** — do not add the
route to `skip_paths`, which stops scanning it entirely and would leave your
admin panel unmonitored.

### 5. Re-publish your config, or diff it

`mergeConfigFrom()` merges top-level keys only, so a published config wins
outright for every key it defines. A file published before v1.3.1 keeps its own
`custom_patterns` and `threat_levels` — meaning none of that release's pattern
or severity fixes have ever reached you.

```bash
cp config/threat-detection.php config/threat-detection.php.bak
php artisan vendor:publish --tag=threat-detection-config --force
# then re-apply your customisations
```

`threat-detection:doctor` reports exactly which options your file predates.

### 6. If your app is API-first

`api_route_filtering` suppresses low **and medium** severity on `/api/` routes
by default — which discards SSRF, directory traversal, LFI and open redirect
after detecting them. Long-standing behaviour, but worth revisiting:

```php
'api_route_filtering' => ['enabled' => true, 'suppress_levels' => ['low']],
```

---

## 1.5.x → 1.6.0

No action required. The shipped config maps the Aadhaar pattern to the
`verhoeff` validator, so 12-digit runs failing the checksum (order ids,
timestamps, barcodes) stop being logged as PII. Published configs are
unaffected — add the key yourself to opt in.

---

## 1.3.x → 1.4.0

**Minimum PHP is now 8.2.** Laravel 10 and 11 remain supported in
`composer.json`, but modern Composer refuses to install them because every
remaining release carries an unpatched advisory. If you are on PHP 8.1, stay on
v1.3.1.

---

## 1.1.x → 1.2.0

Run the new migration — confidence scoring added columns:

```bash
php artisan vendor:publish --tag=threat-detection-migrations
php artisan migrate
```

**Skipping this silently discards every detection.** The insert fails on the
missing `confidence_score` / `confidence_label` columns, the middleware swallows
the error to stay passive, and the dashboard simply looks empty.
