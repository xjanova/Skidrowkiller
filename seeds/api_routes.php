<?php

/**
 * API Routes for Skidrow Killer License System
 *
 * Add these routes to your XManStudio routes/api.php file
 * or create a new route file and include it.
 *
 * Usage: Include this file in your routes/api.php
 *        require __DIR__ . '/skidrow-killer-routes.php';
 */

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Skidrow Killer License API Routes
|--------------------------------------------------------------------------
|
| These routes handle license activation, validation, and demo management
| for the Skidrow Killer desktop application.
|
*/

Route::prefix('v1/license')->group(function () {

    // ============================================
    // Health Check / Ping
    // ============================================

    /**
     * Simple ping endpoint to check server connectivity
     *
     * GET /api/v1/license/ping
     *
     * Response: { "success": true, "timestamp": "2024-01-01T00:00:00Z" }
     */
    Route::get('/ping', function () {
        return response()->json([
            'success' => true,
            'timestamp' => now()->toISOString(),
        ]);
    });

    // ============================================
    // License Activation
    // ============================================

    /**
     * Activate a license key on a machine
     *
     * POST /api/v1/license/activate
     *
     * Request Body:
     * {
     *   "license_key": "XXXX-XXXX-XXXX-XXXX",
     *   "machine_id": "32-char-hash",
     *   "product_id": "skidrow-killer",
     *   "machine_name": "DESKTOP-PC",
     *   "os_version": "Windows 11",
     *   "app_version": "1.0.0"
     * }
     *
     * Response:
     * {
     *   "success": true,
     *   "message": "License activated successfully",
     *   "data": {
     *     "email": "user@example.com",
     *     "customer_name": "John Doe",
     *     "product_name": "Skidrow Killer",
     *     "expires_at": "2025-01-01T00:00:00Z",
     *     "max_devices": 3,
     *     "current_devices": 1,
     *     "features": ["full_scan", "real_time_protection", "network_protection", "registry_monitoring"],
     *     "status": "active"
     *   }
     * }
     */
    Route::post('/activate', [App\Http\Controllers\Api\LicenseController::class, 'activate']);

    // ============================================
    // License Validation
    // ============================================

    /**
     * Validate an existing license
     *
     * POST /api/v1/license/validate
     *
     * Request Body:
     * {
     *   "license_key": "XXXX-XXXX-XXXX-XXXX",
     *   "machine_id": "32-char-hash",
     *   "product_id": "skidrow-killer"
     * }
     *
     * Response:
     * {
     *   "success": true,
     *   "message": "License is valid",
     *   "data": {
     *     "expires_at": "2025-01-01T00:00:00Z",
     *     "features": ["full_scan", "real_time_protection", ...],
     *     "status": "active"
     *   }
     * }
     */
    Route::post('/validate', [App\Http\Controllers\Api\LicenseController::class, 'validate']);

    // ============================================
    // License Deactivation
    // ============================================

    /**
     * Deactivate a license from a machine
     *
     * POST /api/v1/license/deactivate
     *
     * Request Body:
     * {
     *   "license_key": "XXXX-XXXX-XXXX-XXXX",
     *   "machine_id": "32-char-hash",
     *   "product_id": "skidrow-killer"
     * }
     *
     * Response:
     * {
     *   "success": true,
     *   "message": "License deactivated successfully"
     * }
     */
    Route::post('/deactivate', [App\Http\Controllers\Api\LicenseController::class, 'deactivate']);

    // ============================================
    // License Status
    // ============================================

    /**
     * Get license status by key
     *
     * GET /api/v1/license/status/{license_key}
     *
     * Response:
     * {
     *   "success": true,
     *   "data": {
     *     "license_key": "XXXX-XXXX-XXXX-XXXX",
     *     "status": "active",
     *     "license_type": "yearly",
     *     "expires_at": "2025-01-01T00:00:00Z",
     *     "activations": 1,
     *     "max_activations": 3
     *   }
     * }
     */
    Route::get('/status/{license_key}', [App\Http\Controllers\Api\LicenseController::class, 'status']);

    // ============================================
    // Demo / Trial
    // ============================================

    /**
     * Start a demo/trial period
     *
     * POST /api/v1/license/demo
     *
     * Request Body:
     * {
     *   "machine_id": "32-char-hash",
     *   "product_id": "skidrow-killer",
     *   "machine_name": "DESKTOP-PC"
     * }
     *
     * Response:
     * {
     *   "success": true,
     *   "message": "Demo started",
     *   "data": {
     *     "expires_at": "2024-01-08T00:00:00Z",
     *     "features": ["basic_scan", "real_time_protection"]
     *   }
     * }
     */
    Route::post('/demo', [App\Http\Controllers\Api\LicenseController::class, 'startDemo']);

    /**
     * Check demo/trial status
     *
     * POST /api/v1/license/demo/check
     *
     * Request Body:
     * {
     *   "machine_id": "32-char-hash",
     *   "product_id": "skidrow-killer"
     * }
     *
     * Response:
     * {
     *   "success": true,
     *   "data": {
     *     "is_valid": true,
     *     "days_remaining": 5,
     *     "expires_at": "2024-01-08T00:00:00Z"
     *   }
     * }
     */
    Route::post('/demo/check', [App\Http\Controllers\Api\LicenseController::class, 'checkDemo']);
});

/*
|--------------------------------------------------------------------------
| Update API Routes
|--------------------------------------------------------------------------
*/

Route::prefix('v1/updates')->group(function () {

    /**
     * Check for software updates
     *
     * GET /api/v1/updates/{product_id}/check
     *
     * Headers:
     *   X-License-Key: XXXX-XXXX-XXXX-XXXX (optional, for licensed users)
     *
     * Response:
     * {
     *   "update_available": true,
     *   "latest_version": "1.1.0",
     *   "release_notes": "Bug fixes and improvements...",
     *   "download_url": "https://xmanstudio.com/downloads/skidrow-killer/1.1.0",
     *   "release_url": "https://xmanstudio.com/products/skidrow-killer/releases/1.1.0",
     *   "published_at": "2024-01-15T00:00:00Z",
     *   "is_pre_release": false,
     *   "requires_license": false
     * }
     */
    Route::get('/{product_id}/check', [App\Http\Controllers\Api\UpdateController::class, 'check']);

    /**
     * Get authorized download URL (for licensed users)
     *
     * POST /api/v1/updates/{product_id}/download
     *
     * Headers:
     *   X-License-Key: XXXX-XXXX-XXXX-XXXX
     *
     * Response:
     * {
     *   "success": true,
     *   "download_url": "https://xmanstudio.com/downloads/skidrow-killer/1.1.0?token=xxx",
     *   "expires_at": "2024-01-01T01:00:00Z"
     * }
     */
    Route::post('/{product_id}/download', [App\Http\Controllers\Api\UpdateController::class, 'getDownloadUrl']);
});
