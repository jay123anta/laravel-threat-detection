<?php

use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Http\Controllers\ThreatLogController;

Route::prefix(config('threat-detection.api.prefix', 'api/threat-detection'))
    ->middleware(config('threat-detection.api.middleware', ['api']))
    ->group(function () {

        // {id} is numeric: the actions type it as int, so anything else
        // failed with a TypeError — a 500 — instead of a 404.
        Route::get('/threats', [ThreatLogController::class, 'index']);
        Route::get('/threats/{id}', [ThreatLogController::class, 'show'])->whereNumber('id');

        Route::get('/stats', [ThreatLogController::class, 'stats']);
        Route::get('/summary', [ThreatLogController::class, 'summary']);
        Route::get('/live-count', [ThreatLogController::class, 'liveCount']);

        Route::get('/by-country', [ThreatLogController::class, 'byCountry']);
        Route::get('/by-cloud-provider', [ThreatLogController::class, 'byCloudProvider']);
        Route::get('/top-ips', [ThreatLogController::class, 'topIps']);
        Route::get('/timeline', [ThreatLogController::class, 'timeline']);
        Route::get('/ai-threats', [ThreatLogController::class, 'aiThreats']);

        Route::get('/ip-stats', [ThreatLogController::class, 'ipStats']);
        Route::get('/correlation', [ThreatLogController::class, 'correlation']);
        Route::get('/export', [ThreatLogController::class, 'export']);

        Route::get('/exclusion-rules', [ThreatLogController::class, 'exclusionRules']);

        // Writes switch detection OFF for everyone, which is a different
        // privilege from reading the log. They are checked against
        // api.write_guard ('role' by default) regardless of api.guard.
        Route::middleware('threat-dashboard-auth:api,write')->group(function () {
            Route::post('/threats/{id}/false-positive', [ThreatLogController::class, 'markFalsePositive'])->whereNumber('id');
            Route::delete('/exclusion-rules/{id}', [ThreatLogController::class, 'deleteExclusionRule'])->whereNumber('id');
        });
    });
