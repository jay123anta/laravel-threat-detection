# Changelog

All notable changes to `jayanta/laravel-threat-detection` will be documented in this file.

## [1.9.0] - 2026-09-28

Two things in one release.

**Fixes to defects that ship in 1.8.0 — upgrade for these whatever else you
do.** One invalid byte in the User-Agent, or a header long enough, stopped a
request's attacks being logged on strict MySQL. A false-positive click could
create a site-wide exclusion on a path the attacker chose, or on the site root.
A detection regex that failed was read as clean. A credential sent under a
prefixed name, such as `X-Partner-Api-Key`, was stored in cleartext. The exports
could ban addresses the operator had whitelisted or marked as false positives.
Slack alerts rendered markup from the request, and the CSV export could split a
cell where a spreadsheet evaluates it. `/stats` failed on PostgreSQL, and the timeline put a whole year
in one bucket on SQLite. All are under Security and Fixed below.

**An AI-attacker detection line, every part of it opt-in and off by default:**
probes for exposed model infrastructure, injection aimed at the LLM that will
read your logs, attempt-level actor signals with mutation chains, payload
clusters and retry bursts, a research-backed actor risk score, optional bot
identity from `jayanta/laravel-ai-guard`, and a dashboard that shows web
attacks and AI-related threats in separate sections. Every figure cited below
was checked against its source. With everything off, 1,863 of the 1,864 tests
that shipped with 1.8.0 pass unchanged. The other is the inventory of API
routes, which exists to fail when one is added, and did for `/ai-threats`.

The suite grew to 2,356 tests. Verified on Laravel 10.50.3, 11.56.1, 12.69.2
and 13.33.0, on MariaDB 10.4 and PostgreSQL 16, and with PCRE JIT disabled —
where everything passes but the 1 MB timing budgets, which are set for the
JIT; at the 8 KB the package actually scans, every pattern stays in budget.
See [UPGRADING.md](UPGRADING.md#18x--190) — nothing is required, but a few
behaviours changed.

### Security

- **One invalid byte in the User-Agent stopped a request's attacks being
  logged.** Every detection in a request is written in one batched INSERT, and
  the User-Agent was stored exactly as sent. A strict MySQL connection —
  Laravel's default — rejects a string that is not valid UTF-8 for a text
  column, so appending `\xFF` to the header failed the whole statement and the
  attack beside it was never recorded. PostgreSQL rejects the same bytes. The
  test suite ran on SQLite, which stores anything, so nothing noticed.
  Reproduced on MariaDB 10.4 before the fix and verified after it; the test
  now runs in CI against MySQL 8.0.

  Invalid sequences are now replaced before storing, and control characters —
  C0, DEL, the C1 range some terminals honour as escape introducers, and the
  bidirectional overrides that reorder how text displays ("Trojan Source") —
  are stored as visible `\xNN` / `\uNNNN` text, so a stored header cannot
  repaint the terminal, or disguise itself in the log viewer, of whoever reads
  it later. Right-to-left letters are untouched. Ordinary traffic, including valid
  non-ASCII, is stored exactly as before, and detection is unchanged: the
  scanner in `sqlmap/1.8 \x1b[2J\xFF` is still identified.

  The stored URL gets the same treatment. Symfony already normalises a URL
  that arrives through the server, so that half is defence in depth.

  Length did the same thing. Both columns are TEXT, 65,535 bytes on MySQL,
  and neither value was bounded — so a User-Agent or URL past that size failed
  the INSERT, and escaping made it easier to reach: a 20 KB header of control
  bytes is stored as 80 KB. nginx and Apache refuse headers that long by
  default, but Go-based servers such as FrankenPHP accept a megabyte, and
  operators raise nginx's buffers for large cookies. The stored copies are now
  cut at 8 KB on a character boundary and end `…[truncated]`; detection still
  reads the whole value. Reproduced on MariaDB 10.4 before the fix.

- **A false-positive click could silence a detection site-wide, on a path the
  attacker chose.** Marking a row as a false positive builds an exclusion rule
  from its label and URL path, and the path was matched with `fnmatch()` — so
  it was a glob, written by whoever sent the request. A request for `/*`
  carrying an injection, marked as noise, became a permanent rule silencing
  that label on every path. `[a-z]*` and backslashes misbehaved the same way,
  and such rules did not even match their own row's path.

  A rule built from a logged row now matches that row's path exactly. Rules
  already stored are fixed too, with no migration, because the decision is
  made by the rule's origin. A rule an operator writes by hand is still a
  glob. Exclusions are the part of a detector that quietly ratchets — across
  nine years of SigmaHQ rules they were added 5.4 times for every one
  removed, and 64.1% of path exclusions were satisfiable by an unprivileged
  attacker ([arXiv:2608.31062](https://arxiv.org/abs/2608.31062)).

  The site root reached every path by another route. Its path is empty, and
  the rule stored it as `NULL` — which on a rule means "every path" — so
  marking a detection on the home page as noise, the most common place for
  one, silenced that label site-wide. `/0` did the same, and so did a URL
  `parse_url()` could not read. A rule built from a row now always carries
  that row's path, the root included; `NULL` on such a rule, including rules
  earlier versions stored, now means the root. A row whose path cannot be
  stored exactly — unreadable, or longer than the 255-character column — is
  refused with 422 and left unmarked rather than given a wider rule, and the
  rule is created before the row is marked, so a failure leaves neither.

- **A detection regex that failed was read as "no threat".** PHP stops
  catastrophic backtracking with `pcre.backtrack_limit`, and `preg_match()`
  then returns `false` — which the matcher treated exactly like a non-match.
  So the limit that exists to stop a denial of service turned an input that
  made one pattern blow up into a silent bypass of that pattern. The v1.8.0
  audit rewrote one pattern that failed this way; this handles the failure
  mode itself, for every pattern, shipped or custom.

  A request that makes a pattern fail is now reported as
  `[engine] Pattern Evaluation Failure` (medium) instead of passed, after the
  per-request cap so padding cannot push it out, and the failing pattern is
  named once in the log. Backtracking in NIDS rule matching made Snort up to
  1.5 million times slower and let 4.0 kbps perpetually disable it (Smith,
  Estan and Jha, ACSAC 2006); the ReDoS SoK
  ([arXiv:2406.11618](https://arxiv.org/abs/2406.11618)) lists PHP's limits as
  its defence — which is why the detector has to notice when they fire.

  Normalisation had the same hole: a replace that fails returns `null`, which
  emptied the payload, so every pattern saw nothing. Reproducible with PCRE
  JIT disabled, as on some hardened hosts; a failed step now leaves the text
  as it was. CI runs that test with JIT off.

- **A credential under a prefixed name was stored in cleartext.** Masking by
  field name compared names exactly, so `api_key` was masked and
  `X-Partner-Api-Key` was not — nor `X-Vault-Token`, `X-Amz-Security-Token`,
  `X-Webhook-Secret`, `Proxy-Authorization`, or a body field such as
  `stripe_secret`. Every header but `Cookie` and `Authorization` is kept with
  the row, so a legitimate client whose request tripped a pattern left its key
  in `threat_logs`, readable by default by any signed-in user of the API: the
  class of the 1.8.0 advisory, one naming convention over. A listed name now
  also covers any name ending in `_<name>`; one that only starts with it, such
  as `password_hint`, is still kept. In the URL the prefix is matched by a run
  of at most 64 characters, because an unbounded one backtracked once per
  character and a long enough parameter name made redaction, which fails
  closed, blank the whole URL.

- **The exports banned addresses the operator had cleared.** A row marked as a
  false positive — the operator's own statement that it was not an attack —
  still produced a ban and counted toward `--min-hits`, and an address on
  `whitelisted_ips` was exported like any other. Both are now left out. A
  private or reserved address is still exported, because some installs mean to
  ban internal clients, but under a `# WARNING` comment and a log line: the
  usual way one gets there is a proxy `TrustProxies` does not know about, where
  every request appears to come from the proxy and banning it blocks everyone.

- **Queued alerts carried the Slack webhook URL.** The URL is a credential —
  anyone holding it can post to the channel — and it was serialised into every
  alerting job, so on a database or Redis queue it was written to `jobs`, and
  to `failed_jobs`, which nothing prunes. The job now reads it from config when
  it runs; a job queued by an earlier version still carries one and is still
  honoured.

- **A nested marker could end the spotlighted region early.** Spotlighting
  wraps attacker text in markers so an LLM reading the export can tell data
  from instructions, and removes any marker the text already carries — in
  one pass. A marker nested inside the other, twice, lost the inner ones and
  the pieces joined into a whole closing marker, so the text after it read as
  outside the untrusted region. Removal now repeats until nothing changes.

- **Slack alerts rendered markup from the request.** Slack reads `&`, `<` and
  `>` as markup in attachment fields, and its documentation says values must
  escape them. The alert's URL is the requester's, path and all, so a request
  for `/<!channel>` notified the whole channel, and `<http://…|Open the
  dashboard>` rendered as a link whose visible text says anything, in the room
  where the people who respond to attacks read. Defanging the URL's scheme and
  dots did not reach markup in the middle of it. Every field is now escaped.

- **The CSV export could split a cell where a spreadsheet evaluates it.**
  `fputcsv()` escapes with a backslash by default, which RFC 4180 does not
  know: a `"` after a `\` is written undoubled. PHP reads that back, but Excel
  and LibreOffice end the cell at the quote and start a new one with what
  follows — so a URL carrying `\",=…` became a cell beginning with `=`, and
  the formula guard, which checks where each value starts, never saw it. The
  export is now written to RFC 4180, with every quote doubled.

- **`only_paths` compared the path as sent, still percent-encoded**, while
  Laravel's router matches the decoded path, so a request could reach a
  scoped route and fall outside the scope meant to cover it. Either spelling
  now brings a path into scope. The lists that narrow scanning —
  `skip_paths`, `content_paths`, `auth_paths` — still compare the raw path,
  so an encoding can widen what is scanned and never narrow it. Only installs
  that set `only_paths` are affected; it is empty by default.

- **The exports' `# Filters:` comment repeated `--since` and `--min-hits`
  verbatim.** Neither has to parse for rows to be exported, so a newline in
  either put the rest of the value on a line of its own — in the fail2ban
  format, a line of a script run as root. Operator input, the same trust level
  as `--jail`, which 1.8.0 already refuses to interpolate; the comment now stays
  one line.

### Added

- **AI-infrastructure probe tracking, opt-in via `THREAT_DETECTION_AI_PROBES=true`.**
  37 paths covering Ollama's REST API, the OpenAI-compatible surface, MCP
  servers, agent configuration and instruction files, and dated paths for known
  AI-application CVEs. Logged at `high`, because almost no public Laravel app
  serves these: a request for one is a deliberate hunt for exposed model
  infrastructure, not broad spraying.

  The list is not guesswork. It is the set of endpoints attackers were observed
  hitting by Ollure, a honeypot emulating the Ollama API, across 290,887
  interactions from 2,793 unique source IPs over 84 days
  ([arXiv:2609.29757](https://arxiv.org/abs/2609.29757)).

  **Off by default.** With it off, this release reports exactly what 1.8.0
  reported — verified by running the detection suite against both and comparing
  all 429 tests case by case, not by count.

  Route-aware: a pack path that a real route in the app serves — a tags API at
  `/api/tags`, a chat widget at `/api/chat` — is the app's own traffic and is
  not logged. A fallback or a single-parameter catch-all (an SPA's `{any}`)
  answers every path, so it does not count. Also covers the Anthropic-compatible
  `/v1/messages`, OpenAI `/v1/responses` and Gemini `/v1beta/models` shapes,
  probed through misconfigured proxies for leaked paid keys (GreyNoise: 80,469
  sessions in 11 days across 73+ model endpoints).

  Works with a config published before this release. The pack lives inside
  `probe_tracking`, which every published config already has, and Laravel
  merges package config at the top level only — so the published block would
  have hidden the pack and `THREAT_DETECTION_AI_PROBES=true` done nothing. The
  provider fills that one key from the package when it is missing, and leaves
  everything the operator wrote as written.

- **Actor risk scoring, opt-in via `THREAT_DETECTION_ACTOR_SCORE=true`.**
  Read-only ranking of who to look at first, computed on demand from
  `threat_logs` plus `threat_actor_signals` when available. Exposed at
  `correlation?type=actors`. Nothing is written; nothing runs during a request.

  Six terms — peak severity, persistence, diversity, kill-chain progression,
  mutation, cadence — which **add rather than average**. A weighted average has
  a proven ceiling: when every event scores the same value, the average equals
  that value however many events there are, so a persistent attacker scores
  like a single request and can never cross a higher threshold. The additive
  shape used here reached 90.8% recall at 1.20% false positives over 10,654
  cases ([arXiv:2602.11247](https://arxiv.org/abs/2602.11247)), and the
  multi-dimensional approach it follows measured AUROC 0.92 against 0.72 for
  severity alone ([arXiv:2609.02465](https://arxiv.org/abs/2609.02465)).

  Persistence saturates and is scaled by peak severity, so repetition amplifies
  real evidence instead of manufacturing it — unscaled, six low-severity
  detections scored 70/100 on their own. Cadence is the weakest term by design
  and cannot carry a score alone. Every term is returned with the score, since
  a ranking heuristic that will not explain itself is not actionable.

  Cadence is measured on the moments an actor first sent each distinct
  payload, which needs actor signals, and is zero without them. It is never
  computed from `threat_logs` rows: their five-minute deduplication leaves one
  row per type per window, so a probe re-requested for half an hour produced
  rows 300 seconds apart and earned the bonus for the package's own dedup
  window. It is scripted regularity, not a sign of AI — timing features added
  nothing to agent detection once removed by backward elimination
  ([arXiv:2607.26935](https://arxiv.org/abs/2607.26935)).

  Kill-chain progression requires reconnaissance *before* exploitation, and
  the gap is returned as `time_to_exploit_seconds`. A kill chain is a
  transition: across 400 autonomous attack runs the first exploit followed
  recon by about 15–30 s, and the authors recommend detecting that phase
  transition over command signatures
  ([arXiv:2605.30096](https://arxiv.org/abs/2605.30096)). An exploit followed
  later by a probe is two events, and no longer scores as a chain.

  The default weights come from the source formula, where they were tuned for
  multi-turn LLM conversations rather than HTTP actors: a considered starting
  point, not a transferred result.
- **Mutation-chain and payload-cluster detection**, reading the actor-signals
  table. Both are read-only aggregates on `ThreatCorrelationService`, exposed as
  `correlation?type=mutations` and `correlation?type=clusters`, and both return
  an empty list when signals are off or unmigrated.

  A mutation chain is one actor sending many distinct surface forms of the same
  attack — the bypass loop an adaptive attacker produces and a fixed scanner
  list does not. The reported figure is distinct *variants*: counting
  fingerprints would score the loop as a single event, since normalisation is
  what makes the mutations converge, and counting rows would overstate it.

  A payload cluster is one fingerprint arriving from many actors, which is how a
  campaign behind rotating egress still shows up. A single shared fingerprint is
  ignored as background noise; the report requires several payloads shared by
  the same set of actors.

  `getCorrelationSummary()` gains `mutation_chains` and `payload_clusters`
  **only when signals are enabled**, so an install that has not opted in
  receives exactly the keys it did before.

  **Retry bursts** (`correlation?type=retries`) are the complement: one actor
  sending many *different* payloads of one attack class. A chain is one
  payload in many encodings; an attacker that writes a new payload each time
  leaves no chain at all — and that is how a generating attacker iterates, an
  LLM-driven exploitation agent converging in 10–40 newly generated attempts
  ([arXiv:2603.00960](https://arxiv.org/abs/2603.00960)). Counted by distinct
  fingerprint, so a re-encoded payload is not counted twice. Adaptive, not
  evidence of AI.
- **Actor signals, opt-in via `THREAT_DETECTION_ACTOR_SIGNALS=true`.** A new
  `threat_actor_signals` table recording attempt-level evidence that
  `threat_logs` cannot hold, written *before* both the confidence floor and the
  five-minute deduplication — the two gates that otherwise destroy it.

  Substrate, not a detection: nothing reports a threat or changes what
  `threat_logs` receives. The detections that read it come later; this fills it.

  Each row carries two hashes. The **fingerprint** hashes the payload after
  normalisation and so collapses encoding differences; the **variant** hashes it
  as it arrived and collapses nothing. A mutation chain is many variants sharing
  one fingerprint — counting fingerprints would score it as a single event,
  because normalisation is what makes them converge. Measuring LLM-generated
  payload variants found structural distance high while semantic distance stayed
  low, and recommended shifting from syntactic to semantic similarity
  ([arXiv:2605.03619](https://arxiv.org/abs/2605.03619)); this package has
  normalised to a fixed point since v1.3.0, so the fingerprint is taken there.

  Bounded three ways: clean traffic writes nothing, a repeated variant writes
  nothing inside the dedupe window, and `max_per_actor_per_window` caps one
  actor. The cap uses the cache like the DDoS counter, so it is per-process on
  the `array` driver.

  The payload itself is never stored — only truncated SHA-256 hashes, because
  normalisation runs before redaction and the hashed text can contain
  credentials.

  Requires `php artisan vendor:publish --tag=threat-detection-migrations` and a
  migrate. Off by default; verified unchanged against the previous release
  across 692 detection, export and redaction tests compared case by case.

- **The threat log treated as an injection vector, opt-in.** Two independent
  switches, both off by default:

  `THREAT_DETECTION_LLM_INJECTION=true` reports injection-shaped content —
  chat-template control tokens, instruction overrides, triage manipulation,
  prompt exfiltration, encoded-payload instructions — as a threat, scoped to
  query, body and headers.

  `THREAT_DETECTION_SPOTLIGHT_EXPORTS=true` wraps the attacker-controlled cells
  of the CSV export in an explicit trust boundary, so a log pasted into an LLM
  says which parts of itself are data rather than instructions. A payload
  containing the closing marker has it stripped first, so it cannot end the
  region early.

  The reason: this table stores attacker-controlled text, and operators paste
  that text into an LLM to triage it. Prompt injection planted in log fields
  succeeded 83.4% of the time on average across GPT-4o, Claude 3.5 Sonnet and
  Llama-3-70B with no defences, and the most effective carriers — JSON bodies
  at 88.9%, User-Agent and Referer at 83-86% — are exactly the fields stored
  here ([arXiv:2607.14493](https://arxiv.org/abs/2607.14493)). Spotlighting is
  a mitigation, not a fix: on its own it cut success to 51.4%, and to 8.4% only
  layered with other defences.

  Enabling detection costs roughly ten extra regexes on clean traffic. Prompt
  injection is prose, and the keyword pre-screen looks for punctuation-shaped
  markers, so these patterns carry no category in order to run on segments the
  pre-screen would skip. Category-mapped patterns still skip as before.

  Off by default, verified the same way as the probe pack: the detection,
  export and redaction suites run against the previous code and against this,
  compared case by case — 692 tests, same set, same status.

  Two more patterns catch instructions a human cannot see: runs of Unicode Tag
  characters and binary zero-width runs. With tool access and a decoding hint,
  models followed such hidden instructions 98–100% of the time
  ([arXiv:2603.00164](https://arxiv.org/abs/2603.00164)). They match the
  JSON-escaped form segments are stored in — a pattern for the raw bytes, the
  obvious way to write it, would never fire — and their thresholds clear flag
  emoji and the joiners used in emoji and Indic scripts.
- **Per-path probe severity.** A `probe_tracking.paths` value may now be
  `['label' => ..., 'level' => ...]` as well as a plain string, so one path can
  differ from `default_level`. The string form is unchanged.
- **Second-source bot identity, opt-in via `THREAT_DETECTION_AI_GUARD=true`.**
  Reads the `ai-guard.verdict/1` convention published by
  `jayanta/laravel-ai-guard` 3.1+ and adds two terms to the actor score:
  `impersonation` (+0.25) when a client's claimed identity failed every check,
  and `attribution` (−0.25) when it held up.

  No dependency in either direction. The events and request attribute are read
  by name; nothing is imported, and with ai-guard absent the listeners are never
  called. Every payload is checked against the schema string, so a future
  `verdict/2` is ignored rather than misread.

  The asymmetry is the design. Crawler impersonation is a deliberate technique —
  16.3% of 1,000 sites saw Googlebot impersonation — and it exists to inherit
  the trust sites extend to crawlers. So verification only *discounts*, never
  exempts, and the discount is withdrawn entirely from an actor that reached
  the exploitation stage: trust signals are imitable
  ([arXiv:2607.18659](https://arxiv.org/abs/2607.18659)), and identity-based
  classification catches 8–18% of bots
  ([arXiv:2603.28546](https://arxiv.org/abs/2603.28546)). A verified scraper
  earns no discount, and an identity verdict never scores an actor this package
  detected nothing from.

  Off by default, and with it off the score's `components` keep exactly their
  six keys.

- **The dashboard shows web attacks and AI-related threats in separate
  sections.** A health strip says which detection features are on — a
  switched-off feature reads *off*, never *0* — then web attacks, then
  AI-related threats in two panels (probes for model infrastructure; content
  written for an LLM to read), then adaptive behaviour, the actor ranking, and
  volume last.

  "AI-related" describes what was *targeted*, not who attacked: the largest
  campaigns against LLM endpoints have been ordinary scanners, and a
  three-month honeypot deployment found 8 possible AI agents in 8.1 million
  interactions ([arXiv:2410.13919](https://arxiv.org/abs/2410.13919)). So
  mutation chains and payload clusters sit in their own section, labelled
  *possibly automated — not evidence of AI*, and nothing is labelled an AI
  attacker on behaviour alone.

  Behind it: `/threats`, `/stats`, `/timeline`, `/top-ips` and `/by-country`
  take an optional `category=ai|traditional` and return exactly what they
  did without it; `/threats` rows carry `ai_family`; and a new
  `GET /ai-threats` feeds the AI section and reports which features are on,
  with `null` rather than `[]` for an analysis that never ran. Rows are
  classified by exact stored type against the AI packs, so no column is added
  and rows logged before the split are classified too, including after a pack
  is switched off.

  The false-positive dialog now states what it creates before creating it: a
  permanent exclusion for that label, on that path only.

### Fixed

- **`/stats` failed on every PostgreSQL install.** It counted foreign IPs
  with `is_foreign = 1`, and PostgreSQL, which has a real boolean type,
  rejects `boolean = integer` — so the endpoint behind the dashboard's
  headline cards returned an error. The value is now bound as a boolean.
  Verified on PostgreSQL 16, where a new test file sweeps every read endpoint,
  the write paths and the actor-signal queries; it runs in a new CI job.
- **A retention period that was not a number of days deleted everything.**
  `threat-detection:purge` cast `--days` with `(int)`: a negative value put the
  cutoff in the future and a word became 0, and both delete every row. The
  scheduler passes `THREAT_DETECTION_RETENTION_DAYS` straight through, so a
  typo in `.env` — `ninety`, `-1` — emptied the log every night. `--days` must
  now be a whole number, 0 or more (0 by hand still empties the table, as
  documented); the scheduled purge needs 1 or more, schedules nothing
  otherwise, and `doctor` reports it. A non-numeric
  `actor_signals.retention_days` no longer wipes the signals either.
- **On memcached, deduplication never engaged.** The five-minute mark was
  keyed `threat_logged:{ip}:{type}`, and every type contains a space, which
  memcached's text protocol refuses — so each read and write failed silently
  and every attacking request wrote its own row and sent its own alert. The
  key is hashed on memcached; other stores keep the key they had.
- **`/stats` and `threat-detection:stats` failed on SQL Server**, which the
  README lists as supported: they counted today's rows with `DATE()`, which
  SQL Server does not have. They now use the `CAST(... AS DATE)` the other
  date queries already used.
- **A probe's level is normalised.** Probe levels were stored as configured,
  so `High` or a typo was recorded but matched no severity filter, count or
  `notify_levels` on PostgreSQL and SQLite. They are lower-cased, and a value
  that is not high, medium or low falls back to the pack's level, then
  `default_level`, then `medium`, with a warning — as custom patterns already
  did.
- **A failed geo lookup was cached for seven days.** `enrich` cached each
  address's result with `Cache::remember()`, and a failed lookup returns a
  result too — every field null — so after "fix the provider and run it
  again" the rerun read the cached failures, asked nobody and failed the same
  way for a week; `--force` re-applied the cache. Only a resolved answer is
  cached now, and a failure cached by an earlier version counts as a miss.
- **Deleting an exclusion rule logs the scope it actually had.** The log line
  wrote `path_pattern ?? '*'`, so a rule built from a site-root row was
  recorded as covering every path. It now carries a `scope` — `exact path: /…`,
  `glob: …` or `every path` — computed the way the matcher applies it.
- The API reads `per_page`, `limit` and `days` with `input()`. It used
  `Request::get()`, which Symfony 8 removed and Laravel keeps only as a
  deprecated alias that consults request attributes before the query string.
- **`threat-detection:doctor` checks two things the package depends on but
  cannot see from a request.** It warns when `whitelisted_ips` or an `ip` guard
  sits behind `TrustProxies` at `*`, which honours `X-Forwarded-For` from
  whoever connects directly — so an app reachable around its proxy lets a
  client claim a whitelisted address, which is never scanned, or an allowed
  one, which opens the dashboard. And in production it warns when retention is
  off, since IP addresses, URLs and user agents are then kept indefinitely and
  are personal data under GDPR. The README said a wrong whitelist match "fails
  safe"; it fails open, and now says so.
- **`threat-detection:doctor` missed options added inside an existing config
  block.** It compared top-level keys only, so a published config lacking
  `probe_tracking.ai_infrastructure` was reported as current. It now compares
  blocks of named options at any depth — never data maps such as probe paths
  or patterns — and checks the opt-in features that are switched on: a
  missing actor-signals table, scoring without signals, the AI pack with
  probe tracking off, and the ai-guard integration without ai-guard.
- **The timeline and summary put a whole year in one bucket on SQLite** — the
  default database for a new Laravel app. Both grouped by
  `CAST(created_at AS DATE)`, and SQLite, which has no DATE type, returns the
  leading number: every row of 2026 landed in a bucket called `2026`, and the
  dashboard's chart, which formats dates as strings, never drew. SQLite now
  uses `DATE(created_at)`; other drivers keep the cast. Found by executing the
  dashboard's own JavaScript against real API output. Verified on SQLite and
  on MariaDB, which now runs in CI.
- `threat-detection:purge` now sweeps actor signals even when no `threat_logs`
  rows aged out. The command returns early when nothing matches `--days`, so an
  install whose logs were all recent would never have purged the table that
  grows fastest.
- A malformed `probe_tracking.paths` entry — no label, empty label, or a
  non-string — is now skipped instead of being indexed. Previously a malformed
  *wildcard* entry that matched a request produced a probe row with an empty
  label; malformed exact paths were already inert, because `isset()` is false
  for null.
- The API validates its free-text inputs. `keyword`, `ip`, `type`, `country`
  and `cloud_provider` must be strings of at most 255 characters, and a
  false-positive `reason` at most 1,000; anything else answers 422. `keyword`
  went into three `LIKE` clauses at any length, and an array in its place, or
  in `reason`, answered 500.

## [1.8.0] - 2026-09-06

Three audits, in sequence: a full audit of the test suite, a second audit of
the fixes that came out of it, and a security audit treating the package as an
attack surface rather than as a detector. Seven defects from the first, five
more from the second, and sixteen findings from the third — every one of which
had been shipping.

The suite grew from 365 tests to 1,854 in the process, and the new tests are
the regression guards for everything below. Each is a reproduction that was
confirmed to fail before its fix, with a positive control asserting the good
case still works, so "the bad case is blocked" cannot be satisfied by blocking
everything.

Verified on all four supported Laravel majors (10.50.3, 11.56.1, 12.69.1,
13.30.1).

### Security

- **Plaintext credentials were written to `threat_logs`.** Any request that
  tripped any detection while also carrying a password field stored that
  password in cleartext, for the whole retention period, readable by anyone
  with dashboard or database access. A bot spraying SQL injection at a login
  form produced one row per attempt, each holding a real user's password. If
  the credential was in the query string it landed in the `url` column too.

  The cause was one character. Every scanned segment is `json_encode`d before
  matching, so a form field arrives as `{"password":"…"}` while the credential
  patterns are written for the wire form (`password=…`) — the closing quote
  sits between the key and the separator and the match fails. Six of the seven
  credential patterns were affected. Because no label fired, the redaction
  added in v1.7.1 had nothing to mask and never ran. `auth_paths` made it
  worse: it deliberately suppresses those labels on `/login` and `/register`,
  which guaranteed redaction could not run on the paths where passwords are
  most likely to be present.

  Redaction no longer depends on a pattern having fired. Request data is masked
  by *field name* — passwords, API keys, tokens, session ids and card data —
  before it is encoded for storage, so every value type and any nesting depth
  is covered: a numeric PIN, a null, an array of tokens or a nested object are
  masked as readily as a string. Names are compared after folding case,
  normalising `-` and `_`, and dropping a leading `x-`, so the header
  spellings (`X-Api-Key`, `x-auth-token`) resolve to the same entry as the body
  ones (`api_key`, `auth_token`). A second pass covers credentials that appear
  in string form — a query string in the `url` column, or one embedded in
  another field's value. The DDoS row, written on its own path and previously
  skipping redaction entirely, is covered too.

  The list is configurable through the new `redact.fields` key, but its default
  lives in code rather than only in `config/threat-detection.php`.
  `mergeConfigFrom()` merges top-level keys only, so an application that
  published its config before this release keeps its own `redact` block
  wholesale and would never receive a config-only default — which would have
  left exactly the installs that had been storing cleartext passwords still
  storing them, silently, after upgrading. Config now overrides the default
  rather than enabling it, and an explicit empty array still switches it off.

  The patterns themselves are deliberately unchanged: making them match the
  JSON form would fire "Password Exposure" on every legitimate login. Nor does
  masking blind the detector — an attack delivered *through* a password field
  is still detected, because scanning happens before masking. That is the
  distinction from `safe_fields`, which stops the field being scanned at all.
- **Command and config injection in the blocklist and fail2ban exports.**
  `ip_address` was interpolated unescaped into generated nginx and apache
  directives and into a `#!/bin/bash` script an operator runs as root, so a
  newline in that column became a new directive or a new command, and a
  `$(...)` became a substitution at run time.

  Symfony validates `$request->ip()`, which is what kept this out of reach from
  an ordinary request — but that is a guarantee made in a dependency, for one
  write path, and these commands asserted nothing about a value they were
  turning into root-consumed configuration. Every emission site now validates
  before writing: six across the two export commands plus the API CSV export.
  A row whose `ip_address` is not an address is skipped and logged, so a
  blocklist that loses entries says so.

  This also closes two directives that were valid but catastrophic:
  `deny 0.0.0.0/0;` (an empty column produced a rule denying every address) and
  `deny ;`.

  Not closed by this, and worth knowing: an application that trusts proxies
  still lets a client choose *which valid* address is recorded, so an attacker
  can nominate a third party and have your generated rules ban them. That value
  is a well-formed IP and no validation can catch it — it belongs to your
  `TrustProxies` configuration.

- **Write endpoints accepted cross-origin cookie-authenticated requests.**
  Marking a detection a false positive, and deleting an exclusion rule, could
  be driven from any page an authenticated administrator happened to visit.
  Deleting an exclusion rule leaves no record, so the damage was silent.

  Both now require a CSRF token when the request is authenticated by session.
  `_token`, `X-CSRF-TOKEN` and the encrypted `X-XSRF-TOKEN` are all accepted,
  the last because axios-based SPAs send only that. Token-authenticated clients
  are unaffected — enforcement is conditional on the request actually having a
  session, so nothing that works today stops working. The routes were not moved
  into the `web` group.

- **Geo enrichment ran over cleartext HTTP by default.** The endpoint default
  is now HTTPS, and a failed lookup never retries over HTTP — asserted for both
  an HTTPS rejection and a TLS connection failure. On-path attackers could
  previously choose what got written into your `country_name`, `city` and `isp`
  columns, which are read straight into the dashboard and the CSV export.

  A run in which every lookup failed now exits non-zero instead of reporting
  success. A *partial* failure still exits 0, and addresses that are private or
  malformed are skipped rather than counted as failures, so an install whose
  only traffic is local is not told enrichment failed.

- **Geo responses were stored with no length or type validation.** A hostile or
  compromised provider could return 300 characters for a 100-character column;
  on a strict-mode database that raised, and the exception took the whole
  enrichment run down with it, leaving every later row unenriched. Values are
  now bounded to the column width on a character boundary, and arrays and
  objects are discarded rather than coerced.

- **A scanner behind a browser user agent was not identified.** The check read
  "if it looks like a browser, stop" — so `sqlmap/1.5 (Mozilla/5.0 compatible)`
  was never compared against the scanner list at all, and appending a browser
  token to any scanner user agent suppressed the detection entirely. A
  browser-shaped agent now short-circuits only when it matches nothing on any
  configured list. The false-positive noise floor is unchanged, verified
  byte-for-byte against the previous behaviour.

- **`max_detections_per_request` could be filled with noise.** The cap was
  applied in discovery order, so padding a request with cheap low-severity
  matches pushed the real attack out of the budget. Matches are now ranked by
  severity before the cap is applied, and the scan may exit early only once the
  cap is full of high-severity matches — below that it keeps looking. Equal
  severities keep discovery order.

- **The CSV sanitizer anchored on the first character only.** A formula behind
  a leading space, tab or carriage return was not neutralised. Exported CSVs
  also now carry `Content-Type` protection; see *Changed*.

- **`--jail` was interpolated unquoted into a generated root-run script.** The
  value comes from the operator's own command line, so this is the mildest item
  here — but a fail2ban jail name has a known shape and the output is a script
  run as root. Anything outside `[A-Za-z0-9_-]+` is now refused with an error
  rather than quoted, because a jail name containing a space or a semicolon is
  a typo, and quoting it would produce a script that runs happily and bans
  nothing.

### Fixed

- **A non-numeric `ddos.threshold` returned a 500 on every request.** The value
  was assigned straight into an `int` typed property while the container was
  *building* the middleware — before `handle()` runs, so the `try/catch` that
  keeps the detector passive was not yet on the stack. Values from `.env`
  arrive as strings, so `THREAT_DETECTION_DDOS_THRESHOLD=1k` or a stray quote
  was enough to take the whole application down. Both DDoS settings now fall
  back to their documented default and log the reason once. Numeric strings
  such as `"300"` keep working exactly as before.

  Both are also floored at 1. `is_numeric()` accepts negatives and zero, and
  both are quietly destructive in opposite directions: a threshold of zero or
  below makes the very first request a flood, so every client is logged as a
  DDoS; a window of zero or below expires the counter as fast as it is written,
  so a real flood is never detected at all.

- **LDAP injection detection was switched off by 1.5 KB of padding.** The
  pattern had two greedy `.*` under `/s` over a subject built from its own
  character class, which backtracks quadratically. Appending about 1,500 `(`
  characters to a real LDAP injection exhausted `pcre.backtrack_limit`, and
  `preg_match()` returning `false` is indistinguishable from "no threat".
  Rewritten with negated classes and possessive quantifiers: same acceptance
  set, no backtracking, and a sweep of all 158 patterns against 21 classes of
  adversarial input now finds nothing that abandons a match at the size the
  package scans.

- **Hex and unicode escapes were never actually decoded.** `json_encode`
  escapes a backslash as two, and the escape decoders required exactly one, so
  they consumed the second backslash of the pair and left the first behind — a
  hex-escaped `<` normalized to `\<` rather than `<`, and the XSS pattern
  stopped matching. Both decoders now accept a run of backslashes. The README
  has always listed these among the techniques the pipeline defeats; the
  existing tests passed because they assert only the evasion *flag*, which is
  matched on the un-normalized text and was never affected.

- **Two stacked evasion techniques defeated the normalization pipeline.** The
  decode sequence ran once, in a fixed order, so any encoding a later step
  revealed was never seen by an earlier one: a SQL comment written as HTML
  entities survived the comment strip, an escape sequence hidden behind two
  layers of percent encoding was never decoded, and a doubly entity-encoded
  payload decoded one level and stopped. The sequence now repeats until a pass
  changes nothing, up to three times. IIS `%uXXXX` encoding is now decoded as
  well as flagged, so a `%u`-encoded attack is identified rather than merely
  reported as "someone used IIS encoding".

- **The category pre-screen skipped patterns after a comment strip.** Removing
  a SQL comment leaves a space behind, so `system/*​*​/(` normalized to
  `system (` and the `rce` category keyword `system(` no longer matched —
  taking the whole category out of play. Categories are now matched against the
  normalized payload and a whitespace-free view of it. This only ever enables
  more patterns to run, so it cannot introduce a false positive.

- **`relaxed` mode discarded every single-signature attack.** It set a minimum
  confidence of 40 while also subtracting 10 from every score, so one match
  scored at most 35 — 25 from a request body — and was dropped silently. Only
  an attacker announcing themselves with a scanner user agent (+25) could clear
  the bar. In practice the mode was a two-signature minimum, offered as "only
  high-severity patterns trigger" and recommended to content-heavy sites least
  likely to notice. The floor is now 25, the lowest score a lone high-severity
  match can produce.

- **`flushCaches()` missed one warn-once flag.** `$ddosCacheWarned` was never
  reset, so the "cache driver does not support atomic increment" warning could
  not be emitted again after a config change — which is what `flushCaches()`
  exists for under Octane.
- **The scheduled retention purge deleted nothing.** `threat-detection:purge`
  asks for confirmation before deleting. Symfony marks input non-interactive
  only when `--no-interaction` or `-n` is present — it does not detect the
  absence of a terminal — and the scheduler built a plain
  `artisan threat-detection:purge --days=90`. Under cron the prompt was
  reached, read EOF, and cancelled. Retention appeared configured, ran every
  night, and removed nothing.

  If you have retention enabled, expect the first run after upgrading to delete
  a backlog.

### Changed

- `redact.fields` is a new config key and its default lives in code. Publish
  the config again if you want to customise it.
- `relaxed` mode's confidence floor is 25, was 40.
- Blocklist and fail2ban exports skip rows whose `ip_address` is not an
  address, and refuse a malformed `--jail`.
- API responses carry `X-Content-Type-Options: nosniff` and a `Referrer-Policy`,
  so a JSON or CSV response cannot be re-interpreted as HTML by a browser that
  sniffs.
- `threat-detection:enrich` defaults to `https://ip-api.com/json` and exits
  non-zero when every lookup failed. Override with
  `THREAT_DETECTION_GEO_ENDPOINT`.
- `threat-detection:stats` reports **Recorded Detections**, not "Total
  Threats", and states the deduplication window underneath. The dashboard card
  is relabelled to match. The numbers have not changed — a detection is written
  once per IP per type per five minutes, and the old label invited them to be
  read as attempt volume, which they never were. That deduplication is what
  stops a flood becoming a write per request, so it stays.

### Notes

Verified against a corpus of legitimate-but-attack-shaped traffic before and
after: the false-positive noise floor is byte-for-byte unchanged, and an attack
delivered through a redacted field is still detected.

Detection costs about 15 % more per request than before — measured, on this
hardware, as 0.25 ms to 0.28 ms for an ordinary GET and 0.71 ms to 1.1 ms for a
maximally hostile 8 KB body. That is the price of decoding until the payload
stops changing instead of once. Clean traffic short-circuits the loop before
the first pass when the text contains no character any decoder could act on.

## [1.7.2] - 2026-08-27

### Fixed

- **`guzzlehttp/guzzle` was an undeclared dependency.** Three places in `src/`
  use Laravel's HTTP client — the geo lookup in `threat-detection:enrich` and
  the Slack webhook fallback in both the synchronous and queued write paths —
  but guzzle appeared nowhere in `composer.json`. It reached the test suite
  transitively on most dependency resolutions, so this surfaced only on the
  Laravel 10 CI leg, where `Http::response()` fatalled with
  `Class "GuzzleHttp\Psr7\Response" not found`. It is now a dev requirement,
  so the tests resolve it on every leg, and a `suggest` so the runtime need is
  documented. It stays out of `require`: detection itself makes no outbound
  request, and forcing an HTTP client on every install for two optional
  features would be wrong.

- **`threat-detection:enrich` reported success having enriched nothing.**
  Without an HTTP client every lookup failed inside `fetchGeoData()`'s
  best-effort catch, and the command still printed "Enrichment complete!". It
  now refuses up front with the command that fixes it. `threat-detection:doctor`
  reports the same condition.

- **The v1.7.1 note about the Sanctum import was wrong, and is now true.** That
  release claimed the `class_exists()` probe had been inlined so an optional
  package was no longer imported. It had been — and then Pint's
  `fully_qualified_strict_types` fixer hoisted it straight back into a `use`
  statement before the tag was cut, so v1.7.1 shipped with the import intact.
  All three optional-class probes (Sanctum and both Guzzle checks) now use
  string literals, which that fixer leaves alone. Behaviour was never affected:
  a `use` statement does not autoload, so `class_exists()` answered correctly
  throughout.

## [1.7.1] - 2026-08-27

### Added

- **Tests for the three commands that shipped without any.** `purge` (including
  the cascade that removes exclusion rules orphaned by a delete), `stats`, and
  `enrich` - which sends every IP it looks up to a third party and previously
  had nothing asserting its SSRF guard, its private-range skip or its field
  mapping. `Http::preventStrayRequests()` now runs in the base TestCase, so no
  test can reach the network unnoticed.
- **Tests for `ThreatCorrelationService` and `ThreatAlertSlack`.** The
  correlation aggregates were only reached through two API endpoints that
  asserted a 200 and an envelope shape, never the numbers. The Slack alert had
  never been executed at all, including the URL defanging.
- **Quality gates.** PHPStan level 5 via larastan and Pint on the `laravel`
  preset, both enforced by a dedicated CI job, plus a coverage job gated by an
  in-repo threshold script rather than a third-party service.
- **Contributor scaffolding.** `CONTRIBUTING.md`, `UPGRADING.md`, a PR template
  and issue templates that ask for `threat-detection:doctor` output first.
  Dependabot watches composer and actions.
- **`ThreatCorrelationService`.** The reporting queries moved out of
  `ThreatDetectionService`, which had grown past 1,900 lines by carrying both
  the request-time detection path and after-the-fact analysis.
  `ThreatDetectionService` still exposes all five methods and delegates, so the
  facade and every existing call site are unchanged.

### Fixed

- `ThreatCorrelationService` was resolved by auto-wiring while its three sibling
  services were bound as singletons; it is now bound alongside them.
- The service provider imported `Laravel\Sanctum\SanctumServiceProvider` for a
  `class_exists()` probe. Sanctum is a `suggest`, not a requirement, so the
  import read as a hard dependency; the check is inlined.
- Removed a `class_exists(Schedule::class)` guard that could never be false -
  `illuminate/console` is a hard requirement.
- `phpunit.xml` declared an empty `<source><include>`, so `--coverage` produced
  nothing. It now includes `src`.
- The `[1.3.2]` changelog entry, lost when 3cf0e32 rewrote the top of this file
  for v1.4.0, is restored from its tag.
- Seven config environment variables were absent from the README, including
  `THREAT_DETECTION_HOME_COUNTRY`, which defaults to `IN` and silently drives
  the `is_foreign` flag for every installation outside India.
- The "Skip Paths" config comment banner sat above the "Only Paths" banner, so
  `only_paths` inherited the wrong heading and `skip_paths` had none.
- `actions/checkout` bumped v4 to v7; v4 targets Node 20, which GitHub runners
  now force onto Node 24.

## [1.7.0] - 2026-08-12

Detection *gap* fixes: patterns that were configured, matched their input, and
still never fired. **Expect more entries than before, not fewer.** Minor rather
than patch, because the detection surface widens (a new `path` scanning
context, a new `pii` category, new `context_weights` keys) and because of the
exclusion-rule change below.

> **Before upgrading, read these four.**
>
> **1. Two things now require more privilege than before.** Marking a false
> positive and deleting an exclusion rule are checked against the new
> `api.write_guard`, which defaults to `role` — if your user model has no
> `hasRole()`, set `THREAT_DETECTION_API_WRITE_GUARD=auth`. And exclusion rules
> now match the pattern label exactly rather than by substring (see Changed).
> Reading the log and the dashboard are unaffected by both.
>
> **2. If your app serves a bare `/admin`, `/test`, `/debug`, `/console`,
> `/backup` or `/internal` route**, each will now log a low-severity entry per
> IP every 5 minutes. Delete the offending pattern from your published
> `custom_patterns` — do **not** reach for `skip_paths`, which bypasses
> scanning on that route entirely and would leave your admin panel, the
> highest-value target in the app, completely unmonitored.
>
> **3. Re-publish your config, or at least diff it.** `mergeConfigFrom` merges
> only top-level keys, and your published file wins outright for any key it
> defines. A config published before v1.3.1 therefore keeps its own
> `custom_patterns` and `threat_levels` — so none of v1.3.1's pattern or
> severity corrections have ever reached you. Verified on a live app: its
> published `Localhost SSRF` pattern still lacked the `(?<!\d)` guard and was
> logging `Chrome/120.0.0.0` in the user-agent as SSRF, the exact false
> positive v1.3.1 fixed. Run
> `php artisan vendor:publish --tag=threat-detection-config --force` after
> backing up your customisations, or hand-merge the two files.
>
> **4. If your app is API-first**, consider
> `'api_route_filtering.suppress_levels' => ['low']`. The default also
> suppresses medium, which discards SSRF, directory traversal, LFI and open
> redirect on `/api/` routes after detecting them. This is long-standing
> behaviour, not new here, but the new flow test made it visible.
>
> Two guarantees from earlier releases are preserved and now have regression
> tests: ordinary numeric data (timestamps, invoice numbers, SKUs) is still
> never logged as PII (the v1.6.0 checksum work), and the `Authorization`
> header is still not scanned (the v1.3.1 false-positive fix).

### Security

- **Disabling a detection now requires elevated access.** Marking a threat as a
  false positive and deleting an exclusion rule both silence a detection type
  for everyone, but they sat behind the same authentication as reading the log
  — so with the shipped `['api', 'auth:sanctum']` any authenticated user of the
  host application could switch a detection off, with no authorization check
  and no record of who did it.

  Those two routes are now checked against a separate
  `api.write_guard`, which defaults to `role`. Read endpoints and the dashboard
  are untouched, so an upgrade does not take the dashboard away from an
  existing install; only the two destructive endpoints tighten. It accepts the
  same `none|auth|role|ip` values as `guard`, so set
  `THREAT_DETECTION_API_WRITE_GUARD=auth` if your user model has no
  `hasRole()`, or `=none` to restore the previous behaviour. The dashboard's
  false-positive button explains a 403 rather than looking broken, and the
  doctor reports an open write guard.

- **Geo enrichment discloses its cleartext transport.** `threat-detection:enrich`
  sends the attacking IPs it looks up to a third party over plain HTTP, where
  an on-path observer can read them and forge the replies. The endpoint moves
  to `enrichment.endpoint` so it can be pointed at an HTTPS provider, and the
  command now states which provider it is about to contact and how many
  addresses it will send. The default stays HTTP deliberately: ip-api.com's
  free tier answers 403 over HTTPS, so defaulting to `https://` would break
  enrichment for every free-tier user — and silently, since a failed lookup is
  swallowed as best-effort. Enrichment remains opt-in; nothing is sent unless
  you run the command.

- **Detected secrets are no longer stored in cleartext.** Detecting sensitive
  data caused that data to be written to the log verbatim: a profile form
  carrying a mobile number, PAN and bank account tripped three PII patterns and
  each of the three rows stored the whole body, kept for the full retention
  period and readable by anyone with dashboard or database access. A PAN in a
  query string landed in the `url` column too. The detector had become a
  second, concentrated copy of exactly the data it exists to warn about.

  When a pattern listed in the new `redact.labels` fires, the value it matched
  is now masked in the stored payload *and* URL. Detection is unaffected — it
  has already happened by then — so the alert, endpoint, field names and
  attacking IP all survive; only the value goes. Attack payloads are left
  intact, since those are evidence rather than secrets. On by default for the
  regional PII and credential labels; set `THREAT_DETECTION_REDACT=false` to
  restore the old behaviour.

  This does not replace `safe_fields`/`safe_paths`: those stop a field being
  *scanned*, this lets you keep scanning and stop storing.

- **Dashboard assets are pinned with Subresource Integrity.** Tailwind, Alpine
  and Chart.js were loaded from CDNs on floating version ranges
  (`cdn.tailwindcss.com`, `alpinejs@3.x.x`, `chart.js@4`) with no integrity
  hashes, so a CDN compromise or a malicious release would have executed
  arbitrary JavaScript in an authenticated admin's session, on the page that
  displays your security data. Now pinned to exact versions with `sha384`
  hashes and `crossorigin`, with a test that fails if a script tag ever loses
  its hash or regains a floating range.

- **The dashboard sends security headers.** `Content-Security-Policy`,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: no-referrer`. Alpine needs `unsafe-inline`/`unsafe-eval`,
  so script-src is an origin allow-list rather than a strict policy; the clause
  that earns its keep is `connect-src 'self'`, which stops a compromised script
  shipping your threat data to another origin. Disable with
  `dashboard.security_headers => false` if you have customised the view.

### Changed

- **Exclusion rules match the pattern label exactly, not by substring.** A rule
  with `pattern_label` `SQL` previously disabled all nineteen SQL patterns, and
  `Admin Path Access` also swallowed `Admin Path Access Attempt` — an unbounded
  blast radius on a control whose whole job is to switch detections off. Rules
  created through `markFalsePositive` have always stored the exact label and are
  unaffected; only hand-inserted rows that relied on partial matching change
  behaviour, and they change in the direction of re-enabling detection.

### Fixed

- **Custom patterns were silently disabled unless the payload happened to
  contain an unrelated attack keyword.** `isPatternRelevant()` returned early
  on an empty category set, before the "unknown label always runs" fallback it
  documented. A user-defined pattern therefore only ran when the request also
  carried a keyword from one of the fifteen built-in categories. The category
  check now consults the label map first and unmapped (format-shaped) labels
  always run, as documented.

- **Shipped regional PII patterns (Aadhaar, PAN, Mobile, Bank Account, IFSC)
  effectively never fired.** They were mapped to the `token` category, whose
  keywords are all credential words (`bearer`, `csrf`, `api_key`, …) that a
  bare Aadhaar or account number never contains. They now key off a new `pii`
  category of field-name words (`aadhaar`, `ifsc`, `account`, `bank`, `mobile`,
  …), which are also added to the pre-screen list so a clean
  `{"aadhaar": "…"}` body reaches the regex stage at all.

  They stay *gated* rather than always-run on purpose. Two of them are bare
  digit runs — `Bank Account Number Detected` is `\d{9,18}` at **high**
  severity with no checksum — so ungating them logged an ordinary checkout body
  (`order_id`, `invoice_no`, `product_sku`) as two high-severity PII threats.
  That is precisely the false-positive class v1.2.0 and v1.6.0 removed, and
  there is now a test pinning it shut. The gate was never wrong here; the
  keyword list was.

- **The request path was never scanned by the pattern engine.** Only the query
  string, body and headers were fed to it, so roughly twenty path-shaped
  patterns (`/.env`, `/.git/`, `/actuator`, `vendor/phpunit/phpunit`,
  `/users/<id>/delete`) could only match when the path fragment appeared inside
  a query or body *value*. A `path` segment is now scanned, exempt from the
  keyword pre-screen (a URL is a few dozen bytes, and `/.env` contains no
  keyword by design). `path` is also selectable in a custom pattern's
  `contexts` list, and has a `context_weights` entry.

  This complements probe tracking rather than duplicating it: when the probe
  tracker (v1.3.0, path list extended in v1.3.1) already flagged the request,
  the path segment is skipped, so a hit on `/.env` still produces exactly one
  row and keeps the stronger `[probe]` label. The pattern engine covers what
  the fixed probe list misses — a nested `/deep/path/vendor/phpunit/…` does not
  match the `/vendor/phpunit/*` probe entry, but does match the pattern.

- **Sensitive-file and endpoint-probe labels were mapped to categories whose
  keywords they can never contain** — `Environment File Access` sat behind the
  `path` category (`../`, `/etc/`, `passwd`), and `/admin`, `/debug`, `/console`
  probes behind `cve` (`phpunit`, `actuator`). The `path` category gained the
  relevant file-name keywords and a new `endpoint` category covers the probes.

- **The `%00`, `%0d%0a` and `%0a` evasion patterns only matched double-encoded
  input.** They ran against segments built from `$request->query()`/`post()`,
  which Laravel has already URL-decoded, so a real single-encoded null byte
  arrived as a raw NUL and a single-encoded CRLF as actual control characters.
  A `raw` segment now carries the still-encoded query string and body; only
  the evasion patterns scan it, and a label already found in a decoded segment
  is not double-counted.

- **A stale `threat_logs` table silently discarded every detection.** An app
  that upgraded the package without publishing and running
  `add_confidence_to_threat_logs_table` has no `confidence_score` /
  `confidence_label` columns, so every insert failed. The middleware swallows
  the exception to stay passive, so the dashboard just stayed empty — which
  reads as "no attacks", not "nothing is being recorded" — while `laravel.log`
  filled with raw SQL errors. Write failures are now explained once, in words
  that name the cause and the two commands that fix it. Found by running the
  package against a live Laravel 10 application, where it was discarding
  100% of detections.

- **A failed DDoS insert muted the flood for five minutes.** v1.3.1 moved the
  dedup mark to after a successful write for the main detection path but not
  for `logDdosThreat()`, which still marked first.

- **Cloud-metadata SSRF was never detected unless the field happened to be
  named `url`.** `169.254.169.254`, `metadata.google.internal` and the
  `xip.io`/`nip.io`/`sslip.io` rebinding hosts are all listed in the `ssrf`
  category, but none were in the pre-screen list, so a body such as
  `{"callback":"http://169.254.169.254/latest/meta-data/"}` was dropped before
  the category check ever ran — only payloads whose key contained `url`,
  `redirect` or `next` got through, by accident. Added to the pre-screen.
  Found by the new end-to-end flow test, not by any unit assert.

- **CSV export sanitized only three of its free-text columns.**
  `action_taken`, `country_name`, `cloud_provider` and `created_at` bypassed
  the formula-injection guard.

- **Context weighting lost the most suspicious context.** A label matching in
  both the query (weight 1.5) and the body (1.0) kept whichever segment was
  scanned last, erasing the score bonus; the highest weight is now kept.

### Added

- **Operator-side decision helpers — the package still never blocks.**
  New facade methods expose decisions so operators can enforce them in their
  own middleware, same architecture as the fail2ban/blocklist exports (we
  supply the intelligence, the operator supplies the refusal):
  `ThreatDetection::isBlocklisted($ip)` reads a new static, operator-maintained
  `blocklisted_ips` config list (`THREAT_DETECTION_BLOCKLISTED_IPS`; CIDR via
  `IpUtils`; `whitelisted_ips` wins on overlap; nothing in the package ever
  adds to it), and `ThreatDetection::isWhitelisted($ip)` exposes the existing
  whitelist check. List entries are trimmed at match time, so a stale published
  config with untrimmed entries still matches. The detection middleware now
  routes its own whitelist check through the same helper (identical semantics,
  single source of truth). A README recipe shows the minimal user-side
  blocking middleware built on the helpers. Default `[]` — zero behaviour
  change. Discussed in #4.

- **`DdosThresholdExceeded` event + read-only flood counter helpers.**
  Crossing `ddos.threshold` now dispatches a `DdosThresholdExceeded` event
  (`$ipAddress`, `$requestCount`, `$threshold`, `$windowSeconds`), throttled
  to once per IP per dedup window — same throttle as the log row, so a flood
  can't drown listeners. `ThreatDetection::ddosRequestCount($ip)` and
  `ThreatDetection::isDdosThresholdExceeded($ip)` peek at the counter without
  incrementing it, so an operator middleware can return its own 429 with
  `Retry-After` in a few lines (see README). Inert on cache drivers where
  DDoS detection is disabled. Discussed in #4.

- **`php artisan threat-detection:doctor`** — one command that checks whether
  detection is actually *working*, not merely installed.

  Every check corresponds to a way this package has been seen to fail silently
  on a real application, where the only symptom is an empty dashboard —
  indistinguishable from "no attacks". It verifies detection is enabled for the
  current environment; that `threat_logs` has every column the writer inserts
  (a missing one discards **every** threat); that the dashboard/API columns and
  the exclusion-rules table exist; that the middleware is genuinely wired to a
  route or group; that a published config has not drifted behind this version;
  that no custom pattern shadows a built-in one; that the cache driver can do
  DDoS counting; and that neither the dashboard nor the API is exposed without
  authentication.

  Each finding prints the command or setting that fixes it. Exits non-zero only
  on a real failure, so it drops straight into CI or a deploy step. One file,
  no new dependencies. Run against the live app that prompted it, it
  independently reported both bugs found by hand above.

- `ThreatDetectionService::flushCaches()` and
  `ProbeDetectorService::flushCaches()` drop the process-lifetime pattern and
  probe-path caches, so a runtime config change takes effect (tests, Octane
  reloads). The test suite previously reached in with reflection.

- **End-to-end process-flow test** (`ProductionFlowTest`). Drives a
  realistic storefront + admin + API route table through the middleware with
  ordinary browser traffic, then with a 14-attack suite, and asserts on what
  reaches `threat_logs`. It pins the shipped-config noise floor and the
  shipped-config attack blind spot as explicit expected values, so either one
  changing becomes a decision someone has to make rather than a surprise in
  production. It also proves the documented tuning removes the noise without
  costing any attack coverage. This is what surfaced the metadata-SSRF gap
  above.

- 20 regression tests covering the gaps above, with payloads that carry no
  incidental keyword. The earlier custom-pattern tests routed every body
  through a helper that appended an email address and a `password` field —
  which is what made the two bugs above invisible. Four of the new tests guard
  the other direction, pinning the earlier false-positive fixes (no PII on
  numeric data, no `Authorization` scanning, no SQL-comment revival, no
  duplicate probe rows) so a future coverage fix cannot quietly undo them
  (262 → 282 tests).

## [1.6.1] - 2026-07-29

Two defensive fixes. No breaking changes; both are covered by regression tests.

### Fixed

- **The `ip` dashboard/API guard failed open on an empty allow-list.** Setting
  `guard = ip` without populating `allowed_ips` (an unset
  `THREAT_DETECTION_DASHBOARD_IPS`, or one that trimmed to nothing) passed the
  `IpUtils::checkIp()` check for every caller, publishing the security
  dashboard to the internet. It now logs a warning and returns 403 — the same
  fail-closed treatment v1.3.1 gave the `role` and unknown-guard branches.

- **Fully encoded payloads slipped past the pre-screen.** A payload encoded end
  to end (`%55%4E%49%4F%4E…` for `UNION…`) contains no readable keyword, so the
  early bailout skipped the segment before the normalizer could decode it. The
  pre-screen now also treats a bare `%` and a backslash as suspicious, so
  percent- and escape-encoded payloads reach the normalization stage.

## [1.6.0] - 2026-07-29

> **Note for default-config users:** the shipped config now maps the Aadhaar
> pattern to the `verhoeff` validator, so 12-digit runs that fail the checksum
> (order ids, timestamps, barcodes) are no longer logged as PII. Genuine
> Aadhaar numbers are still detected — a checksum-invalid number cannot be a
> real Aadhaar number, so no true detections are lost. Published config files
> are unaffected.

### Added

- **Post-match validators (`pattern_validators`) — checksum-aware
  false-positive reduction.** A regex alone can't express every constraint:
  any 12-digit run matches the Aadhaar pattern, but a real Aadhaar number
  also passes the Verhoeff checksum. A pattern label (default or custom) can
  now be mapped to a named validator; a regex hit then only counts as a
  detection when at least one matched value passes it:

  ```php
  'pattern_validators' => ['Aadhaar Number Detected' => 'verhoeff'],
  ```

  Ships with `verhoeff` (Aadhaar) and `luhn` (credit/debit card numbers); the
  default config maps the Aadhaar pattern to `verhoeff`, so timestamps, order
  ids and barcodes are no longer logged as PII while genuine numbers still
  are. If several values match and only one passes, the detection still fires
  (a real number among noise is still a leak). An unknown validator name
  fails open with a one-time warning, so a typo can never silently disable a
  pattern. Fully backward-compatible: configs published before this feature
  don't have the key and keep their exact current behaviour. 14 new tests
  (232 → 246). Contributed by [@davidvandertuijn](https://github.com/davidvandertuijn) in #2.

- **Rich custom patterns — per-pattern `level`, `contexts` and `validator`.**
  A `custom_patterns` entry can now be an array alongside the classic
  `'regex' => 'Label'` string form:

  ```php
  '/\b(?:\d[ -]?){13,19}\b/' => [
      'label'     => 'Card Number Detected',   // required
      'level'     => 'high',                   // low|medium|high — overrides keyword derivation
      'contexts'  => ['query', 'body'],        // query|body|headers — default: all segments
      'validator' => 'luhn',                   // inline post-match checksum
  ],
  ```

  `level` sets the threat level directly instead of deriving it from
  `threat_levels` keywords in the label; `contexts` restricts a pattern to
  specific request segments; `validator` names an inline post-match check and
  takes precedence over the `pattern_validators` label map. String and array
  entries mix freely, and malformed options fail open (scan unrestricted,
  warn once) — a config mistake never silently disables or narrows a
  detection. Fully backward-compatible: existing string-form configs are
  normalized internally and behave exactly as before. 14 new tests
  (246 → 260). Contributed by [@davidvandertuijn](https://github.com/davidvandertuijn) in #3.

## [1.5.0] - 2026-07-28

### Added

- **`safe_paths` — path-aware false-positive control.** Like `safe_fields`, but
  matches by dot-notation *path* into the request (query or JSON/form body)
  instead of by field name anywhere. This is precise for nested JSON APIs: you
  can exempt one field's value — e.g. a search box whose value legitimately
  contains SQL keywords — without exempting that key name everywhere it appears.
  Supports `fnmatch` wildcards:

  ```php
  'safe_paths' => ['search.query', 'filters.*.value'],
  ```

  Fully backward-compatible (defaults to an empty array; `safe_fields` is
  unchanged). Directly addresses the JSON false-positive problem discussed on
  r/PHP — thanks to **u/Deep_Ad1959** for suggesting path-based allow-listing.

No changes to detection behaviour otherwise — all existing patterns scan exactly
as before. 5 new tests (227 → 232).

## [1.4.0] - 2026-07-23

### Added

- **Laravel 13 support.** Widened `illuminate/*` constraints to `^13.0` and dev
  tooling to `orchestra/testbench ^11.0` and `phpunit/phpunit ^12.0`. The package
  now supports Laravel 10, 11, 12, and 13. Based on the approach proposed by
  **@davidvandertuijn** in #1 — thank you!

### Changed

- **Minimum PHP raised to 8.2** (Laravel 13 itself requires PHP 8.3+). PHP 8.1
  reached end of security support in November 2025 and the current Laravel test
  tooling no longer supports it. If you are still on PHP 8.1, stay on v1.3.1.
- **Test methods migrated from the `@test` docblock annotation to the `#[Test]`
  attribute** across all 15 test files (227 methods). PHPUnit 12 (pulled in by
  Laravel 13) removed docblock metadata; `#[Test]` is supported by PHPUnit 10, 11,
  and 12, so Laravel 10/11/12 remain fully compatible.
- The no-op service double in `MiddlewareTest` now uses `createStub()` instead of
  `createMock()` (clears PHPUnit 12 "useless mock" notices).
- **CI matrix** now covers PHP 8.2/8.3/8.4 × Laravel 12 & 13 (Laravel 13 on PHP
  8.3+), with `fail-fast: false`. Laravel 10 & 11 remain supported in
  `composer.json` but are no longer in the CI matrix — they are end-of-life and
  their unpatched security advisories block a clean CI install.

No functional or API changes to detection behaviour.

## [1.3.2] - 2026-07-23

### Changed

- **Minimum PHP raised to 8.2.** PHP 8.1 reached end of security support in
  November 2025, and the current Laravel 10 test tooling (Testbench / PHPUnit)
  no longer supports it, so the `PHP 8.1 / Laravel 10` CI combination could no
  longer install. If you are still on PHP 8.1, stay on v1.3.1.
- **CI matrix updated** to PHP 8.2 / 8.3 / 8.4 x Laravel 10 / 11 / 12 (excluding
  the unsupported PHP 8.4 + Laravel 10 pair), with `fail-fast: false` so every
  cell reports independently. The Laravel-version pin step now also constrains
  `illuminate/console`, `illuminate/events`, `illuminate/bus`, and
  `illuminate/queue` (added in v1.3.1) to the matrix version.

No functional or API changes - detection behaviour is identical to v1.3.1.

## [1.3.1] - 2026-07-23

Correctness and false-positive fixes. No breaking changes: detection is still
passive (never blocks a request), all existing config keys keep working, and
published config files continue to function untouched. 14 new full-cycle
regression tests (213 → 227 tests, 640 → 657 assertions).

### Fixed — detection coverage (previously silent bypasses)

- **JSON request bodies are now scanned.** `buildPayloadSegments()` previously
  read only `$request->post()` (the form-data bag), so payloads sent as
  `application/json` — most modern API traffic — were never inspected. JSON
  bodies are now read via `$request->json()` and scanned like form fields
  (with the same `safe_fields` stripping).
- **A malformed UTF-8 byte no longer disables a segment.** `json_encode()`
  returns `false` on invalid UTF-8, which silently blanked the whole segment
  (e.g. appending `%FF` to a parameter). All segment encoding now uses
  `JSON_INVALID_UTF8_SUBSTITUTE`.
- **`api_route_filtering` can no longer be evaded via the query string.** The
  API-route check now keys off the route path (`$request->path()`) instead of
  the full URL, so appending `?x=/api/` can neither suppress detections nor
  wrongly filter a non-API page.
- **Remapped patterns that never fired now do:** the four NoSQL operator
  patterns (`$ne`, `$gt`, `$regex`, `$where`) are mapped to the `injection`
  category where their keywords live; web-shell signatures (`c99`, `r57`,
  `b374k`, `wso`, `c100`, `FilesMan`) and the space-less Shellshock variant
  (`(){`) and the Drupalgeddon `#pre_render` variant now have matching category
  and pre-screen keywords. Added exploit-recon probe paths
  (`/vendor/phpunit/*`, `/.aws/credentials`, `/.ssh/id_rsa`, `/.git/*`).

### Fixed — false positives (noise reduction)

- **The `Authorization` header is no longer scanned.** Ordinary authenticated
  traffic (Bearer / JWT tokens) was logged as a high-severity `JWT Token Found`
  / `Bearer Token Detected` per IP every 5 minutes. The header is now excluded
  from the headers segment (a token in the query string is still flagged).
- **`Private IP Access`** gained a leading word boundary so UA fragments like
  `Chrome/110.0.0.0` no longer match `10.0.0.0`.
- **`Localhost SSRF`** no longer matches `0.0.0.0` / `127.0.0.1` embedded in a
  longer digit run — a real Chrome user-agent (`Chrome/120.0.0.0`) was being
  logged as SSRF on nearly every request. Genuine `0.0.0.0`/`127.0.0.1` hosts
  still match. (Found by a live end-to-end run, not covered by the unit asserts.)
- **`zap`** (scanner list and confidence attack-tool list) is now matched as
  `owasp zap` / `zaproxy` instead of the bare substring, so integration UAs
  such as `Zapier` are no longer flagged / scored.

### Fixed — severity correctness

- Corrected severities that resolved to the wrong level: `Log4j/Log4Shell` and
  `JNDI` (→ high), `XXE` entity/DOCTYPE (→ high), `IFSC Code` (→ high, matching
  the other PII), web-shell / reverse-shell / encoded-eval (→ high), SQLi
  variant / time-based / benchmark / sleep (→ high), `API Key Exposure`
  (→ high), `File Inclusion` and `JavaScript URI` (→ medium). Removed the
  over-broad `Java` severity keyword that accidentally promoted `JavaScript URI`
  to high (deserialization stays high via the `Serialization` keyword).

### Fixed — hardening & robustness

- **Dashboard/API auth guard now fails closed.** An unrecognised guard value
  (typo) previously fell through and granted access; it now logs a warning and
  returns 403. `guard = role` with a user model that has no `hasRole()` method
  now denies (with a warning) instead of silently allowing.
- **Whitelist/allowed-IP env lists are trimmed** so `"1.2.3.4, 5.6.7.8"` no
  longer breaks the entries after the comma.
- **`export-blocklist` CSV reports the correct level.** `MAX(threat_level)` was
  lexicographic (`medium > low > high`); it now ranks severity numerically.
- **`enrich`** no longer marks unknown-geo IPs as `is_foreign` and skips
  private/reserved ranges (no wasted rate-limited API calls).
- **Dedup cache is marked only after a successful write**, so a failed insert no
  longer mutes a threat type for 5 minutes; within-request dedup is preserved.
- **Corrected default `skip_paths`** (`assets/*`, `css/*`, `js/*`, … instead of
  the never-matching `public/…` prefixes).
- **`purge`** cleans orphaned exclusion rules with a DB-side subquery instead of
  loading every purged id into memory.
- **`vendor:publish --tag=threat-detection-migrations` is idempotent** — already
  published migrations are skipped instead of creating duplicate timestamped
  copies.
- Declared the `illuminate/console`, `illuminate/events`, `illuminate/bus`, and
  `illuminate/queue` dependencies the package already uses.

## [1.3.0] - 2026-03-23

> Never tagged and never published to Packagist - the work below reached users
> as part of v1.3.1. Kept for the historical record.

### Added

- **45 New Detection Patterns** based on OWASP Top 10, CRS, CWE Top 25, and MITRE ATT&CK:
  - CRLF injection, LF injection, null byte injection (CRS 921, CWE-113/626)
  - Shellshock CVE-2014-6271, Spring4Shell CVE-2022-22965, PHPUnit RCE CVE-2017-9841
  - Windows command injection: cmd.exe, PowerShell, wscript, cscript, net user (CRS 932)
  - SVG/HTML event handler XSS, CSS expression XSS (CRS 941)
  - SQL DDL injection (DROP/ALTER/CREATE/TRUNCATE), SQL DML injection (INSERT/UPDATE/DELETE)
  - SQL file operations (INTO OUTFILE, LOAD_FILE), ORDER BY enumeration, HAVING injection, hex strings, UNHEX
  - Java deserialization (base64 `rO0AB` + hex `aced0005` magic bytes)
  - Expanded SSTI: mathematical probe `{{7*7}}`, Jinja2 import, config access, Velocity templates
  - Open redirect detection (CWE-601)
  - LDAP injection and LDAP OR injection (CWE-90)
  - XPath attribute and function injection (CWE-643)
  - PHP assert(), create_function(), preg_replace /e, php_uname(), allow_url_include (CRS 933)
  - HTTP request smuggling CL+TE indicator (CRS 921)
  - GraphQL introspection abuse (__schema, __type)
  - Prototype pollution (__proto__, constructor.prototype)
  - SSI injection (Server-Side Includes)
  - SSRF bypass: hex-encoded localhost (0x7f000001), decimal localhost (2130706433), DNS rebinding (xip.io, nip.io, sslip.io)
  - Drupalgeddon render array injection, Spring Boot actuator probe

- **30 New Bot/Scanner Signatures** (23 → 53 total):
  - Security scanners: Arachni, Netsparker, Qualys, Skipfish, Vega, Wapiti, JoomScan, DroopeScan, Commix, XSStrike, Dalfox, FeroxBuster, FFUF, HTTPX, Subfinder, Katana, Jaeles
  - AI scrapers: GPTBot, ChatGPT, ClaudeBot, Anthropic, ByteSpider, Cohere, Common Crawl
  - Headless browsers: HeadlessChrome, PhantomJS, Selenium, Puppeteer, Playwright
  - Aggressive crawlers: AhrefsBot, SEMRushBot, MJ12Bot, DotBot, PetalBot

- **404 Probe Tracking** — Detects reconnaissance probes hitting known vulnerable paths (`/wp-admin`, `/.env`, `/phpmyadmin`, `/actuator`, etc.). Logged with `[probe]` type tag. 50+ default probe paths. Configurable via `probe_tracking.paths` config. Enabled by default.

- **Fail2ban Export** (`threat-detection:export-fail2ban`) — Export detected IPs in fail2ban-compatible format. Supports `--level`, `--since`, `--min-hits`, `--format=fail2ban|plain`, and `--jail` options.

- **Blocklist Export** (`threat-detection:export-blocklist`) — Export IPs in multiple formats: `plain`, `csv`, `nginx` (deny directives), `apache` (Deny from directives). Same filtering options as fail2ban export.

- **Dashboard Auth Guard** — Configurable authentication for dashboard and API routes via `THREAT_DETECTION_DASHBOARD_GUARD`. Four modes: `none` (default), `auth` (Laravel auth), `role` (Spatie-compatible hasRole), `ip` (IP whitelist). Logs warning when dashboard is accessed without auth.

- **Safe Fields** — New `safe_fields` config to exclude specific form fields from scanning. Reduces false positives on CMS editors, code inputs, and search fields.

- **Expanded Evasion Detection** — 3 new evasion patterns: HTML entity encoding (`&#60;`), Unicode escape sequences (`\u003c`), IIS Unicode encoding (`%u003c`).

### Improved

- **Normalization Pipeline** — Now includes HTML entity decoding, Unicode escape decoding, hex escape decoding, and recursive URL decoding (3 passes max) in addition to SQL comment stripping.
- **Category-Based Lazy Pattern Loading** — Pre-checks keywords per attack category before running regex. Only relevant categories' patterns execute. Reduces regex evaluations by ~80% on average.
- **Early Bailout** — Keyword-based pre-screen skips 175+ regex patterns for clean payloads. Content-type aware — doesn't false-trigger on JSON structural characters.
- **Browser UA Short-Circuit** — Normal browsers (Mozilla/Gecko) skip 70+ scanner/bot str_contains checks. Only headless browser markers are checked.
- **Static Pattern Caching** — Default patterns, evasion patterns, and scanner/bot arrays cached as static properties (no array recreation per request).
- **Probe Path Hash Lookup** — Exact probe paths use O(1) hash table. Only wildcard paths use fnmatch.
- **Payload Deduplication** — Segments built once and reused for both detection and payload logging (eliminated 3 redundant json_encode calls).
- **Batch DB Inserts** — Multiple threats from a single request are written in one INSERT instead of N separate writes.
- **Max Detections Per Request** — Configurable cap (`THREAT_DETECTION_MAX_DETECTIONS`) to stop scanning after N matches. Default: unlimited.
- **Cache Key Optimization** — Direct string keys for dedup cache instead of md5 hashing.
- **127 new full-cycle tests** — 86 → 213 tests, 338 → 640 assertions. Covers all new patterns, bot detection, probe tracking, export commands, dashboard auth, safe fields, and performance.

### Backward Compatibility

- **Zero breaking changes.** All new features use sensible defaults.
- Probe tracking is enabled by default but only adds log entries (passive).
- Dashboard guard defaults to `none`, preserving existing behavior.
- Safe fields defaults to empty array (all fields scanned, same as before).
- Existing published config files continue to work without changes.

## [1.2.0] - 2026-03-11

### Added

- **Route Whitelisting (`only_paths`)** — Scan only specific routes instead of all routes. Dramatically reduces overhead on high-traffic apps. Leave empty (default) to scan everything.
- **Queue Support** — Offload DB writes and Slack notifications to a queue (`THREAT_DETECTION_QUEUE=true`). Detection remains synchronous; only the write is deferred. Uses `StoreThreatLog` job with 3 retries and backoff.
- **Auto-Purge (Retention Policy)** — Automatically delete old threat logs on a daily schedule (`THREAT_DETECTION_RETENTION=true`). Configurable retention period in days.
- **ThreatDetected Event** — Every confirmed threat dispatches a `ThreatDetected` event. Listen to it for custom actions (Telegram alerts, SIEM feeds, blocklists, etc.).
- **Minimum Confidence Threshold** — `THREAT_DETECTION_MIN_CONFIDENCE` config option. Threats below this score are silently ignored and never written to the database.
- **API Rate Limiting** — `THREAT_DETECTION_API_THROTTLE` config option. Auto-applies throttle middleware to all API routes (default: 60 requests/minute).
- **Evasion Resistance** — Payload normalization layer defeats SQL comment insertion (`UNION/**/SELECT`), double URL encoding (`%2527`), and CHAR encoding bypasses (`CHAR(39)`). Evasion attempts are flagged as high severity.
- **SQL CHAR Encoding Detection** — New default pattern catches `CHAR(N)` SQL injection variants.
- **Expanded LFI Protocol Detection** — Added `phar://`, `expect://`, and `input://` to the LFI protocol pattern.
- **Full RFC 1918 Private IP Range** — Fixed private IP detection to cover the full `172.16.0.0/12` range (was only matching `172.16.x.x`).
- **Localhost SSRF with `0.0.0.0`** — Added `0.0.0.0` to the default localhost SSRF pattern.
- **16 new full-cycle feature tests** — End-to-end tests that send HTTP requests through the middleware, verify database records, confidence scores, event dispatch, and queue behavior.
- **4 new middleware unit tests** — Tests for `only_paths` whitelist mode and `only_paths` + `skip_paths` interaction.

### Improved

- **Query Consolidation** — `stats` endpoint and `threat-detection:stats` command reduced from 7-9 separate queries to 1 query using `CASE WHEN` aggregation.
- **N+1 Query Fix** — `detectCoordinatedAttacks()` and `detectAttackCampaigns()` use batch IP fetching with `whereIn()` instead of per-row queries.
- **Pattern Validation Caching** — Custom regex patterns are validated once per process lifecycle and cached statically. Invalid patterns are logged and skipped permanently.
- **Threat Level Lookup Caching** — `getThreatLevelByType()` results cached in a static array to avoid repeated config lookups.
- **Content-Type Awareness** — File upload binary fields are automatically excluded from scanning in multipart requests.
- **Cache Driver Compatibility** — DDoS detection gracefully skips on `file`, `database`, and `null` cache drivers (which don't support atomic increment) with a one-time warning log.
- **CSV Export Security** — Added formula injection prevention (prefixes cells starting with `=`, `+`, `-`, `@`, `\t`, `\r` with a single quote).
- **Log Injection Prevention** — Strips `\n`, `\r`, `\t` from type and URL before writing to Laravel log.
- **SSRF Prevention** — IP validation via `filter_var(FILTER_VALIDATE_IP)` before external API calls in the enrich command.
- **ReDoS Prevention** — Fixed 3 regex patterns (JSP/ASP template, GraphQL query, PHP deserialization) to use bounded negated character classes instead of greedy `.`.
- **Auth Fallback Fix** — Sanctum fallback only adds `auth` middleware when `auth:sanctum` was explicitly present (respects user-configured middleware).
- **Audit Trail** — Exclusion rule deletion now logs rule details for audit purposes.

### Removed

- **SQL Comment Syntax pattern** (`/(--|\#|\/\*)/`) — Removed from default patterns. This was the #1 false positive source (`--` matches CSS classes, CLI flags, markdown, URL slugs). Actual SQL comment evasion is now caught by the new normalization layer. Real SQL attacks continue to be caught by keyword patterns (UNION SELECT, exec, etc.).

### Backward Compatibility

- **Zero breaking changes.** All new features are opt-in with sensible defaults.
- Existing users upgrading from v1.1.0 do not need to change any config, code, or database schema.
- All 70 original tests continue to pass unchanged.
- The removed SQL Comment Syntax pattern was not asserted by any existing test.

## [1.1.0] - Previous release

Initial public release with 130+ detection patterns, dashboard, API, Slack notifications, confidence scoring, and geo-enrichment.
