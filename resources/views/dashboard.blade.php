@extends('threat-detection::layouts.app')

@section('content')
{{--
    Web attacks and AI-related threats are shown in separate sections, because
    they need different responses and often different people.

    "AI-related" describes what was *targeted* — model infrastructure, or an
    LLM that will read the content — not who attacked. The largest campaigns
    against LLM endpoints have been ordinary scanners. Adaptive behaviour
    (many encodings of one payload, one payload from many addresses) gets its
    own section and is never labelled as AI: it is what any iterating or
    automated attacker leaves.

    A feature that is switched off says "off", never "0". A zero reads as
    "nothing happened", which is a different and more dangerous claim.

    Every attacker-supplied value is rendered with x-text (textContent), never
    as HTML.
--}}
<div x-data="threatDashboard()" x-init="loadAll()">

    {{-- Health strip: what is being measured at all --}}
    <div class="flex flex-wrap items-center gap-2 mb-6 text-xs" data-section="health">
        <span class="text-gray-400 uppercase tracking-wide mr-1">Detection</span>
        <template x-for="item in healthItems()" :key="item.label">
            <span class="px-2 py-1 rounded border"
                :class="item.on ? 'border-green-700 bg-green-900/30 text-green-300' : 'border-gray-700 bg-gray-800 text-gray-500'"
                x-text="item.label + ': ' + (item.on ? 'on' : 'off')"></span>
        </template>
    </div>

    {{-- ─────────────────────────── Web attacks ─────────────────────────── --}}
    <section class="mb-10" data-section="web">
        <div class="mb-4">
            <h2 class="text-lg font-semibold text-white">Web attacks</h2>
            <p class="text-sm text-gray-400">Classic attacks on your application — injection, XSS, traversal, scanners and ordinary reconnaissance.</p>
        </div>

        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
            <template x-for="card in [
                { label: 'Detections', key: 'total_threats', color: 'text-white' },
                { label: 'High', key: 'high_severity', color: 'text-red-400' },
                { label: 'Medium', key: 'medium_severity', color: 'text-yellow-400' },
                { label: 'Low', key: 'low_severity', color: 'text-blue-400' },
                { label: 'Unique IPs', key: 'unique_ips', color: 'text-purple-400' },
                { label: 'Today', key: 'today', color: 'text-green-400' },
            ]">
                <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <div class="text-xs text-gray-400 uppercase tracking-wide" x-text="card.label"></div>
                    <div class="text-2xl font-bold mt-1" :class="card.color" x-text="stats[card.key] ?? '-'"></div>
                </div>
            </template>
        </div>

        <div class="bg-gray-800 rounded-lg p-5 border border-gray-700 mb-6">
            <h3 class="text-sm font-semibold text-gray-300 uppercase tracking-wide mb-4">Web attack timeline (7 days)</h3>
            <div style="height: 220px;">
                <canvas id="timelineChart"></canvas>
            </div>
        </div>

        <div class="bg-gray-800 rounded-lg border border-gray-700">
            <div class="p-4 border-b border-gray-700 flex flex-col sm:flex-row gap-3">
                <input type="text" x-model="search" @input="debounceSearch()"
                    placeholder="Search IP, URL, type..."
                    class="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-gray-100 placeholder-gray-400 focus:outline-none focus:border-blue-500">
                <select x-model="levelFilter" @change="loadThreats(1)"
                    class="bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-blue-500">
                    <option value="">All Levels</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
            </div>

            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="text-left text-gray-400 uppercase text-xs border-b border-gray-700">
                            <th class="px-4 py-3">Time</th>
                            <th class="px-4 py-3">IP</th>
                            <th class="px-4 py-3">Type</th>
                            <th class="px-4 py-3">Level</th>
                            <th class="px-4 py-3">Confidence</th>
                            <th class="px-4 py-3">URL</th>
                            <th class="px-4 py-3">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <template x-for="threat in threats.data" :key="threat.id">
                            <tr class="border-b border-gray-700/50 hover:bg-gray-700/30">
                                <td class="px-4 py-2.5 text-gray-400 whitespace-nowrap" x-text="formatDate(threat.created_at)"></td>
                                <td class="px-4 py-2.5 font-mono text-xs" x-text="threat.ip_address"></td>
                                <td class="px-4 py-2.5" x-text="threat.type"></td>
                                <td class="px-4 py-2.5">
                                    <span class="px-2 py-0.5 rounded text-xs font-medium"
                                        :class="levelBadge(threat.threat_level)"
                                        x-text="threat.threat_level"></span>
                                </td>
                                <td class="px-4 py-2.5">
                                    <span class="px-2 py-0.5 rounded text-xs font-medium"
                                        :class="confidenceBadge(threat.confidence_label)"
                                        x-text="(threat.confidence_score ?? 0) + '%'"></span>
                                </td>
                                <td class="px-4 py-2.5 text-gray-400 max-w-xs truncate" x-text="threat.url"></td>
                                <td class="px-4 py-2.5">
                                    <button x-show="!threat.is_false_positive"
                                        @click="markFalsePositive(threat)"
                                        class="text-xs bg-yellow-600/20 text-yellow-400 px-2 py-1 rounded hover:bg-yellow-600/40 cursor-pointer">
                                        FP
                                    </button>
                                    <span x-show="threat.is_false_positive"
                                        class="text-xs text-gray-500 italic">Excluded</span>
                                </td>
                            </tr>
                        </template>
                        <tr x-show="threats.data && threats.data.length === 0">
                            <td colspan="7" class="px-4 py-8 text-center text-gray-500">No web attacks found.</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="px-4 py-3 border-t border-gray-700 flex items-center justify-between text-sm">
                <span class="text-gray-400">
                    Page <span x-text="threats.current_page ?? 1"></span> of <span x-text="threats.last_page ?? 1"></span>
                    (<span x-text="threats.total ?? 0"></span> total)
                </span>
                <div class="flex gap-2">
                    <button @click="loadThreats(threats.current_page - 1)"
                        :disabled="!threats.prev_page_url"
                        :class="threats.prev_page_url ? 'hover:bg-gray-600 cursor-pointer' : 'opacity-40 cursor-not-allowed'"
                        class="px-3 py-1 bg-gray-700 rounded text-gray-300 text-xs">Prev</button>
                    <button @click="loadThreats(threats.current_page + 1)"
                        :disabled="!threats.next_page_url"
                        :class="threats.next_page_url ? 'hover:bg-gray-600 cursor-pointer' : 'opacity-40 cursor-not-allowed'"
                        class="px-3 py-1 bg-gray-700 rounded text-gray-300 text-xs">Next</button>
                </div>
            </div>
        </div>
    </section>

    {{-- ─────────────────────── AI-related threats ─────────────────────── --}}
    <section class="mb-10" data-section="ai">
        <div class="mb-4">
            <h2 class="text-lg font-semibold text-white">AI-related threats</h2>
            <p class="text-sm text-gray-400">
                What was <em>targeted</em>, not who attacked: probes for exposed model infrastructure, and content written for an LLM to read.
                Most of this traffic comes from ordinary scanners.
            </p>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            {{-- (a) AI infrastructure probes --}}
            <div class="bg-gray-800 rounded-lg p-5 border border-gray-700" data-panel="ai-infrastructure">
                <div class="flex items-baseline justify-between mb-1">
                    <h3 class="text-sm font-semibold text-gray-300 uppercase tracking-wide">AI infrastructure probes</h3>
                    <span class="text-2xl font-bold text-orange-400" x-text="panelCount('ai_probes', 'infrastructure_probes')"></span>
                </div>
                <p class="text-xs text-gray-500 mb-3">Requests for Ollama, OpenAI-compatible, MCP and agent-config paths your app does not serve.</p>
                <p x-show="panelOff('ai_probes', 'infrastructure_probes')" class="text-xs text-gray-500">
                    Off. Enable with <code class="bg-gray-700 px-1 rounded">THREAT_DETECTION_AI_PROBES=true</code>.
                </p>
                <div class="space-y-1.5">
                    <template x-for="row in familyRows('ai_infrastructure_probe')" :key="row.type">
                        <div class="flex items-center justify-between text-sm">
                            <span class="text-gray-300" x-text="row.label"></span>
                            <span class="text-xs text-gray-400" x-text="row.count + ' from ' + row.unique_ips + ' IP' + (row.unique_ips === 1 ? '' : 's')"></span>
                        </div>
                    </template>
                </div>
            </div>

            {{-- (b) Content aimed at an LLM --}}
            <div class="bg-gray-800 rounded-lg p-5 border border-gray-700" data-panel="llm-directed">
                <div class="flex items-baseline justify-between mb-1">
                    <h3 class="text-sm font-semibold text-gray-300 uppercase tracking-wide">Content aimed at an LLM</h3>
                    <span class="text-2xl font-bold text-pink-400" x-text="panelCount('llm_injection', 'llm_injection')"></span>
                </div>
                <p class="text-xs text-gray-500 mb-3">Instruction overrides, role markers and triage manipulation — written for a model to read, including the one you may paste this log into.</p>
                <p x-show="panelOff('llm_injection', 'llm_injection')" class="text-xs text-gray-500">
                    Off. Enable with <code class="bg-gray-700 px-1 rounded">THREAT_DETECTION_LLM_INJECTION=true</code>.
                </p>
                <div class="space-y-1.5">
                    <template x-for="row in familyRows('llm_injection')" :key="row.type">
                        <div class="flex items-center justify-between text-sm">
                            <span class="text-gray-300" x-text="row.label"></span>
                            <span class="text-xs text-gray-400" x-text="row.count + ' from ' + row.unique_ips + ' IP' + (row.unique_ips === 1 ? '' : 's')"></span>
                        </div>
                    </template>
                </div>
            </div>
        </div>

        {{-- Recent AI-related rows --}}
        <div class="bg-gray-800 rounded-lg border border-gray-700">
            <div class="px-4 py-3 border-b border-gray-700 text-sm font-semibold text-gray-300 uppercase tracking-wide">Latest AI-related detections</div>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="text-left text-gray-400 uppercase text-xs border-b border-gray-700">
                            <th class="px-4 py-3">Time</th>
                            <th class="px-4 py-3">IP</th>
                            <th class="px-4 py-3">Kind</th>
                            <th class="px-4 py-3">Type</th>
                            <th class="px-4 py-3">Level</th>
                            <th class="px-4 py-3">URL</th>
                            <th class="px-4 py-3">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <template x-for="threat in aiRows" :key="threat.id">
                            <tr class="border-b border-gray-700/50 hover:bg-gray-700/30">
                                <td class="px-4 py-2.5 text-gray-400 whitespace-nowrap" x-text="formatDate(threat.created_at)"></td>
                                <td class="px-4 py-2.5 font-mono text-xs" x-text="threat.ip_address"></td>
                                <td class="px-4 py-2.5">
                                    <span class="px-2 py-0.5 rounded text-xs font-medium"
                                        :class="threat.ai_family === 'llm_injection' ? 'bg-pink-500/20 text-pink-300' : 'bg-orange-500/20 text-orange-300'"
                                        x-text="familyLabel(threat.ai_family)"></span>
                                </td>
                                <td class="px-4 py-2.5" x-text="threat.type"></td>
                                <td class="px-4 py-2.5">
                                    <span class="px-2 py-0.5 rounded text-xs font-medium"
                                        :class="levelBadge(threat.threat_level)"
                                        x-text="threat.threat_level"></span>
                                </td>
                                <td class="px-4 py-2.5 text-gray-400 max-w-xs truncate" x-text="threat.url"></td>
                                <td class="px-4 py-2.5">
                                    <button x-show="!threat.is_false_positive"
                                        @click="markFalsePositive(threat)"
                                        class="text-xs bg-yellow-600/20 text-yellow-400 px-2 py-1 rounded hover:bg-yellow-600/40 cursor-pointer">
                                        FP
                                    </button>
                                    <span x-show="threat.is_false_positive" class="text-xs text-gray-500 italic">Excluded</span>
                                </td>
                            </tr>
                        </template>
                        <tr x-show="aiRows.length === 0">
                            <td colspan="7" class="px-4 py-8 text-center text-gray-500">No AI-related detections.</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </section>

    {{-- ─────────────────────── Adaptive behaviour ─────────────────────── --}}
    <section class="mb-10" data-section="adaptive">
        <div class="mb-4">
            <h2 class="text-lg font-semibold text-white">Adaptive behaviour</h2>
            <p class="text-sm text-gray-400">
                Possibly automated — <strong class="text-gray-300">not evidence of AI</strong>. Many encodings of one payload, or one payload from many addresses,
                is what any iterating attacker or tampering tool leaves, whoever or whatever is driving it.
            </p>
        </div>

        <p x-show="ai.enabled && !ai.enabled.actor_signals" class="text-sm text-gray-500 bg-gray-800 border border-gray-700 rounded-lg p-4">
            Off. Needs actor signals: <code class="bg-gray-700 px-1 rounded">THREAT_DETECTION_ACTOR_SIGNALS=true</code> and the package migrations.
        </p>

        <div x-show="ai.enabled && ai.enabled.actor_signals" class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div class="bg-gray-800 rounded-lg p-5 border border-gray-700" data-panel="mutation-chains">
                <h3 class="text-sm font-semibold text-gray-300 uppercase tracking-wide mb-1">Mutation chains</h3>
                <p class="text-xs text-gray-500 mb-3">One actor, many surface forms of the same payload — iterating to get past a filter.</p>
                <div class="space-y-1.5">
                    <template x-for="chain in (ai.mutation_chains ?? [])" :key="chain.actor_key + chain.fingerprint">
                        <div class="flex items-center justify-between text-sm">
                            <span class="font-mono text-xs text-gray-300" x-text="chain.actor_key"></span>
                            <span class="text-gray-400 text-xs" x-text="chain.label + ' — ' + chain.variant_count + ' variants'"></span>
                        </div>
                    </template>
                    <div x-show="(ai.mutation_chains ?? []).length === 0" class="text-gray-500 text-sm">None in the last hour.</div>
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-5 border border-gray-700" data-panel="payload-clusters">
                <h3 class="text-sm font-semibold text-gray-300 uppercase tracking-wide mb-1">Payload clusters</h3>
                <p class="text-xs text-gray-500 mb-3">The same payloads from several addresses — one campaign spread across IPs.</p>
                <div class="space-y-1.5">
                    <template x-for="cluster in (ai.payload_clusters ?? [])" :key="cluster.actors.join(',')">
                        <div class="flex items-center justify-between text-sm">
                            <span class="text-gray-300" x-text="cluster.actor_count + ' addresses'"></span>
                            <span class="text-gray-400 text-xs" x-text="cluster.labels.join(', ') + ' — ' + cluster.fingerprint_count + ' payloads'"></span>
                        </div>
                    </template>
                    <div x-show="(ai.payload_clusters ?? []).length === 0" class="text-gray-500 text-sm">None in the last hour.</div>
                </div>
            </div>
        </div>
    </section>

    {{-- ───────────────────── Actors to look at first ───────────────────── --}}
    <section class="mb-10" data-section="actors">
        <div class="mb-4">
            <h2 class="text-lg font-semibold text-white">Actors to look at first</h2>
            <p class="text-sm text-gray-400">Across both sections, ranked by accumulated behaviour. A ranking, not a verdict — every term that produced a score is shown.</p>
        </div>

        <p x-show="ai.enabled && !ai.enabled.actor_score" class="text-sm text-gray-500 bg-gray-800 border border-gray-700 rounded-lg p-4">
            Off. Enable with <code class="bg-gray-700 px-1 rounded">THREAT_DETECTION_ACTOR_SCORE=true</code>.
        </p>

        <div x-show="ai.enabled && ai.enabled.actor_score" class="bg-gray-800 rounded-lg border border-gray-700" data-panel="actors">
            <template x-for="actor in (ai.risky_actors ?? [])" :key="actor.actor_key">
                <div class="px-4 py-3 border-b border-gray-700/50">
                    <div class="flex flex-wrap items-center gap-2">
                        <span class="text-xl font-bold w-12" :class="actor.score >= 70 ? 'text-red-400' : (actor.score >= 40 ? 'text-yellow-400' : 'text-gray-300')" x-text="actor.score"></span>
                        <span class="font-mono text-xs text-gray-300" x-text="actor.actor_key"></span>
                        <span class="text-xs text-gray-500" x-text="actor.detections + ' detections, ' + actor.distinct_types + ' kinds'"></span>
                        <span x-show="actor.reached_recon && actor.reached_exploit" class="px-2 py-0.5 rounded text-xs bg-red-500/20 text-red-300">recon → exploit</span>
                        <span x-show="(actor.components?.impersonation ?? 0) > 0" class="px-2 py-0.5 rounded text-xs bg-red-500/20 text-red-300">impersonating a crawler</span>
                        <span x-show="(actor.components?.attribution ?? 0) < 0" class="px-2 py-0.5 rounded text-xs bg-green-500/20 text-green-300">verified crawler (discounted)</span>
                    </div>
                    <div class="text-xs text-gray-500 mt-1" x-text="componentsText(actor.components)"></div>
                </div>
            </template>
            <div x-show="(ai.risky_actors ?? []).length === 0" class="px-4 py-6 text-gray-500 text-sm">No actors scored in the window.</div>
        </div>
    </section>

    {{-- ─────────────────────── Volume, both sections ─────────────────────── --}}
    <section data-section="volume">
        <div class="mb-4">
            <h2 class="text-lg font-semibold text-white">Volume</h2>
            <p class="text-sm text-gray-400">Across both sections. Volume says who is loudest, not who matters most.</p>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div class="bg-gray-800 rounded-lg p-5 border border-gray-700">
                <h3 class="text-sm font-semibold text-gray-300 uppercase tracking-wide mb-4">Top offending IPs</h3>
                <div class="space-y-2">
                    <template x-for="ip in topIps" :key="ip.ip_address">
                        <div class="flex items-center justify-between text-sm">
                            <span class="font-mono text-xs text-gray-300" x-text="ip.ip_address"></span>
                            <div class="flex items-center gap-2">
                                <span class="text-xs text-gray-500" x-text="ip.country_name ?? ''"></span>
                                <span class="bg-red-500/20 text-red-400 px-2 py-0.5 rounded text-xs font-medium" x-text="ip.threat_count"></span>
                            </div>
                        </div>
                    </template>
                    <div x-show="topIps.length === 0" class="text-gray-500 text-sm">No data yet.</div>
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-5 border border-gray-700">
                <h3 class="text-sm font-semibold text-gray-300 uppercase tracking-wide mb-4">Threats by country</h3>
                <div class="space-y-2">
                    <template x-for="country in byCountry" :key="country.country_code">
                        <div>
                            <div class="flex items-center justify-between text-sm mb-1">
                                <span class="text-gray-300" x-text="(country.country_name ?? 'Unknown') + ' (' + (country.country_code ?? '?') + ')'"></span>
                                <span class="text-gray-400 text-xs" x-text="country.count"></span>
                            </div>
                            <div class="w-full bg-gray-700 rounded-full h-1.5">
                                <div class="bg-blue-500 h-1.5 rounded-full" :style="'width: ' + Math.round(country.count / maxCountry * 100) + '%'"></div>
                            </div>
                        </div>
                    </template>
                    <div x-show="byCountry.length === 0" class="text-gray-500 text-sm">Run <code class="bg-gray-700 px-1 rounded">php artisan threat-detection:enrich</code> to populate geo data.</div>
                </div>
            </div>
        </div>
    </section>
</div>

<script>
function threatDashboard() {
    const API = @json($apiPrefix);

    return {
        stats: {},
        threats: { data: [], current_page: 1, last_page: 1, total: 0 },
        aiRows: [],
        ai: {},
        topIps: [],
        byCountry: [],
        search: '',
        levelFilter: '',
        searchTimer: null,
        chart: null,

        get maxCountry() {
            return Math.max(...this.byCountry.map(c => c.count), 1);
        },

        async loadAll() {
            await Promise.all([
                this.loadStats(),
                this.loadThreats(),
                this.loadAiRows(),
                this.loadAi(),
                this.loadTopIps(),
                this.loadByCountry(),
                this.loadTimeline(),
            ]);
        },

        async getJson(path) {
            const r = await fetch(API + path, { credentials: 'same-origin' });
            return (await r.json()).data;
        },

        async loadStats() {
            try { this.stats = await this.getJson('/stats?category=traditional') ?? {}; }
            catch (e) { console.error('Stats load failed:', e); }
        },

        async loadThreats(page = 1) {
            try {
                const params = new URLSearchParams({ per_page: 15, page, category: 'traditional' });
                if (this.search) params.set('keyword', this.search);
                if (this.levelFilter) params.set('level', this.levelFilter);
                this.threats = await this.getJson('/threats?' + params) ?? { data: [], current_page: 1, last_page: 1, total: 0 };
            } catch (e) { console.error('Threats load failed:', e); }
        },

        async loadAiRows() {
            try { this.aiRows = (await this.getJson('/threats?category=ai&per_page=10'))?.data ?? []; }
            catch (e) { console.error('AI rows load failed:', e); }
        },

        async loadAi() {
            try { this.ai = await this.getJson('/ai-threats?days=7') ?? {}; }
            catch (e) { console.error('AI summary load failed:', e); }
        },

        async loadTopIps() {
            try { this.topIps = await this.getJson('/top-ips?limit=10') ?? []; }
            catch (e) { console.error('Top IPs load failed:', e); }
        },

        async loadByCountry() {
            try { this.byCountry = await this.getJson('/by-country') ?? []; }
            catch (e) { console.error('By country load failed:', e); }
        },

        async loadTimeline() {
            try {
                const rows = await this.getJson('/timeline?days=7&category=traditional') ?? [];

                const dates = [...new Set(rows.map(r => r.date))].sort();
                const levels = { high: [], medium: [], low: [] };

                dates.forEach(date => {
                    ['high', 'medium', 'low'].forEach(level => {
                        const row = rows.find(r => r.date === date && r.threat_level === level);
                        levels[level].push(row ? row.count : 0);
                    });
                });

                const ctx = document.getElementById('timelineChart');
                if (this.chart) this.chart.destroy();

                this.chart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: dates.map(d => d.substring(5)),
                        datasets: [
                            { label: 'High', data: levels.high, backgroundColor: 'rgba(239,68,68,0.7)', borderRadius: 3 },
                            { label: 'Medium', data: levels.medium, backgroundColor: 'rgba(234,179,8,0.7)', borderRadius: 3 },
                            { label: 'Low', data: levels.low, backgroundColor: 'rgba(59,130,246,0.5)', borderRadius: 3 },
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            x: { stacked: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#9ca3af' } },
                            y: { stacked: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#9ca3af' } }
                        },
                        plugins: {
                            legend: { labels: { color: '#d1d5db', boxWidth: 12, padding: 16 } }
                        }
                    }
                });
            } catch (e) { console.error('Timeline load failed:', e); }
        },

        healthItems() {
            const on = this.ai.enabled ?? {};
            return [
                { label: 'AI infrastructure probes', on: !!on.ai_probes },
                { label: 'LLM-directed content', on: !!on.llm_injection },
                { label: 'Actor signals', on: !!on.actor_signals },
                { label: 'Actor score', on: !!on.actor_score },
                { label: 'ai-guard identity', on: !!on.ai_guard },
            ];
        },

        // A switched-off pack with no history shows "off", not "0".
        panelOff(flag, total) {
            return !!this.ai.enabled && !this.ai.enabled[flag] && !(this.ai.totals?.[total] > 0);
        },

        panelCount(flag, total) {
            if (!this.ai.enabled) return '-';
            if (this.panelOff(flag, total)) return 'off';
            return this.ai.totals?.[total] ?? 0;
        },

        familyRows(family) {
            return (this.ai.by_type ?? []).filter(row => row.family === family);
        },

        familyLabel(family) {
            return {
                ai_infrastructure_probe: 'AI infrastructure',
                llm_injection: 'Aimed at an LLM',
            }[family] ?? '';
        },

        componentsText(components) {
            if (!components) return '';
            return Object.entries(components)
                .filter(([, value]) => value !== 0)
                .map(([name, value]) => name + ' ' + (value > 0 ? '+' : '') + value)
                .join(' · ');
        },

        debounceSearch() {
            clearTimeout(this.searchTimer);
            this.searchTimer = setTimeout(() => this.loadThreats(1), 400);
        },

        levelBadge(level) {
            return {
                high: 'bg-red-500/20 text-red-400',
                medium: 'bg-yellow-500/20 text-yellow-400',
                low: 'bg-blue-500/20 text-blue-400',
            }[level] ?? 'bg-gray-500/20 text-gray-400';
        },

        confidenceBadge(label) {
            return {
                very_high: 'bg-red-500/20 text-red-400',
                high: 'bg-orange-500/20 text-orange-400',
                medium: 'bg-yellow-500/20 text-yellow-400',
                low: 'bg-green-500/20 text-green-400',
            }[label] ?? 'bg-gray-500/20 text-gray-400';
        },

        // What a false-positive click actually creates, said before the click.
        // An exclusion is permanent and silences that detection on that path
        // for every future request, so its scope is not a detail.
        exclusionScope(threat) {
            const label = String(threat.type ?? '').replace(/^\[[^\]]*\]\s*/, '');
            let path = '/';
            try { path = new URL(threat.url).pathname || '/'; } catch (e) { /* keep '/' */ }
            return { label, path };
        },

        async markFalsePositive(threat) {
            const { label, path } = this.exclusionScope(threat);
            const message = 'Mark this as a false positive?\n\n'
                + 'This creates a permanent exclusion: "' + label + '" will no longer be logged on ' + path + '.\n'
                + 'Other paths are unaffected. Exclusions can be removed from the API.';
            if (!confirm(message)) return;

            try {
                const r = await fetch(API + '/threats/' + threat.id + '/false-positive', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]')?.content ?? '',
                    },
                });
                if (r.ok) {
                    threat.is_false_positive = true;
                } else if (r.status === 403) {
                    // Disabling a detection is gated behind api.write_guard,
                    // which is separate from the guard that let you view this
                    // page. Say so, rather than looking like a broken button.
                    alert('You do not have permission to disable a detection.\n\n'
                        + 'This requires the role set in threat-detection.api.role, '
                        + 'or a different THREAT_DETECTION_API_WRITE_GUARD setting.');
                } else {
                    alert('Failed to mark as false positive.');
                }
            } catch (e) {
                console.error('False positive failed:', e);
                alert('Request failed.');
            }
        },

        formatDate(dt) {
            if (!dt) return '';
            const d = new Date(dt);
            return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
                + ' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
        },
    };
}
</script>
@endsection
