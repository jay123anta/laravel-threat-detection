<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Threat Detection Dashboard</title>

    {{--
        Pinned to exact versions with Subresource Integrity.

        These were floating ranges (cdn.tailwindcss.com, alpinejs@3.x.x,
        chart.js@4) with no integrity hashes, which meant a CDN compromise or a
        malicious release would execute arbitrary JavaScript in the session of
        an authenticated admin — on the page that displays this application's
        security data. With SRI the browser refuses to run a script whose
        content does not match the hash.

        Upgrading a version means recomputing its hash, e.g.:
          curl -sL <url> | openssl dgst -sha384 -binary | openssl base64 -A
    --}}
    <script src="https://cdn.tailwindcss.com/3.4.16"
            integrity="sha384-mS5Uq7sE90lgbBDN8xgf34ibEgbZo4gB3tfLY40ZRle+M188BQw8onzNHg6GUZaA"
            crossorigin="anonymous"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.14.9/dist/cdn.min.js"
            integrity="sha384-9Ax3MmS9AClxJyd5/zafcXXjxmwFhZCdsT6HJoJjarvCaAkJlk5QDzjLJm+Wdx5F"
            crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"
            integrity="sha384-vsrfeLOOY6KuIYKDlmVH5UiBmgIdB1oEf7p01YgWHuqmOHfZr374+odEv96n9tNC"
            crossorigin="anonymous"></script>
    @stack('head')
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen">
    <nav class="bg-gray-800 border-b border-gray-700 px-6 py-3 flex items-center justify-between">
        <div class="flex items-center space-x-3">
            <svg class="w-7 h-7 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
            </svg>
            <span class="text-white text-lg font-semibold">Threat Detection</span>
        </div>
        <div class="text-sm text-gray-400">
            {{ config('app.name', 'Laravel') }} &mdash; Security Dashboard
        </div>
    </nav>
    <main class="max-w-7xl mx-auto p-6">
        @yield('content')
    </main>
</body>
</html>
