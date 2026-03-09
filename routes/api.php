<?php

use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Http\Controllers\ThreatLogController;

Route::prefix(config('threat-detection.api.prefix', 'api/threat-detection'))
    ->middleware(config('threat-detection.api.middleware', ['api']))
    ->group(function () {

        Route::get('/threats', [ThreatLogController::class, 'index']);
        Route::get('/threats/{id}', [ThreatLogController::class, 'show']);

        Route::get('/stats', [ThreatLogController::class, 'stats']);
        Route::get('/summary', [ThreatLogController::class, 'summary']);
        Route::get('/live-count', [ThreatLogController::class, 'liveCount']);

        Route::get('/by-country', [ThreatLogController::class, 'byCountry']);
        Route::get('/by-cloud-provider', [ThreatLogController::class, 'byCloudProvider']);
        Route::get('/top-ips', [ThreatLogController::class, 'topIps']);
        Route::get('/timeline', [ThreatLogController::class, 'timeline']);

        Route::get('/ip-stats', [ThreatLogController::class, 'ipStats']);
        Route::get('/correlation', [ThreatLogController::class, 'correlation']);
        Route::get('/export', [ThreatLogController::class, 'export']);

        Route::post('/threats/{id}/false-positive', [ThreatLogController::class, 'markFalsePositive']);

        Route::get('/exclusion-rules', [ThreatLogController::class, 'exclusionRules']);
        Route::delete('/exclusion-rules/{id}', [ThreatLogController::class, 'deleteExclusionRule']);
    });
