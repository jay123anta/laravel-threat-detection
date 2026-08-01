@extends('threat-detection::layouts.app')

@section('content')
<div x-data="threatDashboard()" x-init="loadAll()">

    {{-- Stats Cards --}}
    <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
        <template x-for="card in [
            { label: 'Total Threats', key: 'total_threats', color: 'text-white' },
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

    {{-- Timeline Chart --}}
    <div class="bg-gray-800 rounded-lg p-5 border border-gray-700 mb-6">
        <h3 class="text-sm font-semibold text-gray-300 uppercase tracking-wide mb-4">Threat Timeline (7 Days)</h3>
        <div style="height: 220px;">
            <canvas id="timelineChart"></canvas>
        </div>
    </div>

    {{-- Threats Table --}}
    <div class="bg-gray-800 rounded-lg border border-gray-700 mb-6">
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
                                    @click="markFalsePositive(threat.id)"
                                    class="text-xs bg-yellow-600/20 text-yellow-400 px-2 py-1 rounded hover:bg-yellow-600/40 cursor-pointer">
                                    FP
                                </button>
                                <span x-show="threat.is_false_positive"
                                    class="text-xs text-gray-500 italic">Excluded</span>
                            </td>
                        </tr>
                    </template>
                    <tr x-show="threats.data && threats.data.length === 0">
                        <td colspan="7" class="px-4 py-8 text-center text-gray-500">No threats found.</td>
                    </tr>
                </tbody>
            </table>
        </div>

        {{-- Pagination --}}
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

    {{-- Bottom Row: Top IPs + By Country --}}
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {{-- Top IPs --}}
        <div class="bg-gray-800 rounded-lg p-5 border border-gray-700">
            <h3 class="text-sm font-semibold text-gray-300 uppercase tracking-wide mb-4">Top Offending IPs</h3>
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

        {{-- By Country --}}
        <div class="bg-gray-800 rounded-lg p-5 border border-gray-700">
            <h3 class="text-sm font-semibold text-gray-300 uppercase tracking-wide mb-4">Threats by Country</h3>
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
</div>

<script>
function threatDashboard() {
    const API = @json($apiPrefix);

    return {
        stats: {},
        threats: { data: [], current_page: 1, last_page: 1, total: 0 },
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
                this.loadTopIps(),
                this.loadByCountry(),
                this.loadTimeline(),
            ]);
        },

        async loadStats() {
            try {
                const r = await fetch(API + '/stats', { credentials: 'same-origin' });
                const json = await r.json();
                this.stats = json.data ?? {};
            } catch (e) { console.error('Stats load failed:', e); }
        },

        async loadThreats(page = 1) {
            try {
                const params = new URLSearchParams({ per_page: 15, page });
                if (this.search) params.set('keyword', this.search);
                if (this.levelFilter) params.set('level', this.levelFilter);

                const r = await fetch(API + '/threats?' + params, { credentials: 'same-origin' });
                const json = await r.json();
                this.threats = json.data ?? { data: [], current_page: 1, last_page: 1, total: 0 };
            } catch (e) { console.error('Threats load failed:', e); }
        },

        async loadTopIps() {
            try {
                const r = await fetch(API + '/top-ips?limit=10', { credentials: 'same-origin' });
                const json = await r.json();
                this.topIps = json.data ?? [];
            } catch (e) { console.error('Top IPs load failed:', e); }
        },

        async loadByCountry() {
            try {
                const r = await fetch(API + '/by-country', { credentials: 'same-origin' });
                const json = await r.json();
                this.byCountry = json.data ?? [];
            } catch (e) { console.error('By country load failed:', e); }
        },

        async loadTimeline() {
            try {
                const r = await fetch(API + '/timeline?days=7', { credentials: 'same-origin' });
                const json = await r.json();
                const rows = json.data ?? [];

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

        async markFalsePositive(id) {
            if (!confirm('Mark this threat as a false positive?')) return;
            try {
                const r = await fetch(API + '/threats/' + id + '/false-positive', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]')?.content ?? '',
                    },
                });
                if (r.ok) {
                    const threat = this.threats.data.find(t => t.id === id);
                    if (threat) threat.is_false_positive = true;
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
