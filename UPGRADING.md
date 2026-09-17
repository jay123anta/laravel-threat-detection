# Upgrading

Only versions with required action are listed. Anything not mentioned upgraded
without changes.

---

## 1.7.x → 1.8.0

A security release. **One step is required of everyone; the rest depend on what
you use.** No public signature changed and nothing needs re-publishing.

```bash
composer update jayanta/laravel-threat-detection
php artisan threat-detection:doctor
```

### 1. Purge `threat_logs` — it may contain passwords

**Required.** Before 1.8.0, any request that tripped a detection while also
carrying a password field stored that password in cleartext, for the whole
retention period. Upgrading stops new ones being written. **It does not remove
the ones already there.**

```bash
php artisan threat-detection:purge --days=0
```

Run it **after** `composer update`, not before. It deletes every row written before
the moment it runs; anything that lands afterwards — including a row written in the
same second, which the purge does not reach — comes from 1.8.0 and is already
masked. Purge first and cleartext rows keep arriving until you upgrade.

If you cannot lose the history, at minimum restrict who
can read it (step 2) and rotate credentials for accounts that signed in while the
package was active — administrators first. Details in the
[security advisory](https://github.com/jay123anta/laravel-threat-detection/security/advisories/GHSA-9jh8-pj82-6ccg).

### 2. Check who can read the API

Not new in 1.8.0, but it is what made step 1 serious. The API is on by default
and guarded only by `auth` — **any logged-in user**, not an administrator. If
your app has public sign-up, restrict it:

```env
THREAT_DETECTION_API_GUARD=role
THREAT_DETECTION_API_ROLE=admin
```

or set `THREAT_DETECTION_API=false` if you do not use it.

### 3. Session-authenticated writes now need a CSRF token

`POST …/threats/{id}/false-positive` and `DELETE …/exclusion-rules/{id}` answer
**419** without one when the request is authenticated by session cookie. `_token`,
`X-CSRF-TOKEN` and the encrypted `X-XSRF-TOKEN` are all accepted.

Nothing to do if you call them with a Sanctum or bearer token — a request with no
session is not asked for one — or if you only use the built-in dashboard, which
already sent it.

### 4. Geo enrichment is HTTPS, and fails loudly

The endpoint default is now `https://ip-api.com/json`, a failed lookup is never
retried over cleartext, and a run in which **every** lookup failed exits non-zero
instead of reporting success.

ip-api.com's free tier rejects HTTPS. If you relied on it, `threat-detection:enrich`
will now fail rather than quietly send your visitors' IP addresses unencrypted.
Point it at a provider you hold a key for, or set it back and accept the
disclosure:

```env
THREAT_DETECTION_GEO_ENDPOINT=http://ip-api.com/json
```

### 5. If retention is enabled, expect a backlog to be deleted

The scheduled purge has never actually run. It reached a confirmation prompt under
cron, read EOF, and cancelled — every night, exiting 0. Retention looked configured
and removed nothing. It now runs with `--no-interaction`, so **the first scheduled
run after upgrading deletes everything older than your retention period at once.**
On a large table that is one long delete; run it by hand at a quiet time if that
matters:

```bash
php artisan threat-detection:purge --days=90
```

### 6. `relaxed` mode now logs something

Its confidence floor was 40, which no single detection could reach, so the mode
silently discarded every attack that was not also announced by a scanner user
agent. It is 25. If you chose `relaxed` for the quiet, expect high-severity rows to
start appearing — those are detections you were not seeing, not new noise.

### 7. Exports are stricter

`export-blocklist` and `export-fail2ban` skip any row whose `ip_address` is not a
valid IP, and log each one they skip. On a healthy install that set is empty. If
you write your own rows to `threat_logs`, entries that were not addresses will
disappear from generated blocklists — which is the intent.

`export-fail2ban --jail` now refuses anything outside `[A-Za-z0-9_-]` and exits 1,
rather than interpolating it into a script you run as root.

### Nothing to do

- Credentials are masked by field name regardless of whether a pattern fired. The
  default list lives in code, so an already-published config is covered without
  re-publishing. Customise it with `redact.fields` — which **replaces** the
  default list rather than adding to it.
- API responses carry `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: no-referrer`.
- `threat-detection:stats` says **Recorded Detections**, not "Total Threats". The
  numbers did not change; the label did, because a detection is written once per
  IP per type per five minutes and the old one invited reading it as attempt
  volume.
- A scanner hiding behind a browser user agent is now identified, and
  `max_detections_per_request` keeps the most severe matches rather than the first
  few. Both can only add rows.

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
