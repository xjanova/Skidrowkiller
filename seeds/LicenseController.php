<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\LicenseKey;
use App\Models\Product;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Carbon\Carbon;

/**
 * License Controller for Skidrow Killer
 *
 * This controller handles all license-related API requests from the
 * Skidrow Killer desktop application.
 */
class LicenseController extends Controller
{
    /**
     * Features available for each license type
     */
    private const TRIAL_FEATURES = [
        'basic_scan',
        'real_time_protection',
    ];

    private const FULL_FEATURES = [
        'basic_scan',
        'full_scan',
        'deep_scan',
        'real_time_protection',
        'behavioral_analysis',
        'registry_monitoring',
        'network_protection',
        'process_injection_detection',
        'auto_quarantine',
        'scheduled_scans',
        'priority_updates',
        'email_support',
    ];

    /**
     * Activate a license key on a machine
     *
     * POST /api/v1/license/activate
     */
    public function activate(Request $request)
    {
        $validated = $request->validate([
            'license_key' => 'required|string',
            'machine_id' => 'required|string|size:32',
            'product_id' => 'required|string',
            'machine_name' => 'nullable|string|max:255',
            'os_version' => 'nullable|string|max:255',
            'app_version' => 'nullable|string|max:50',
        ]);

        // Find the license
        $license = LicenseKey::where('license_key', strtoupper($validated['license_key']))
            ->whereHas('product', fn($q) => $q->where('slug', $validated['product_id']))
            ->first();

        if (!$license) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid license key',
            ], 404);
        }

        // Check if license is revoked
        if ($license->status === LicenseKey::STATUS_REVOKED) {
            return response()->json([
                'success' => false,
                'message' => 'This license has been revoked',
            ], 403);
        }

        // Check if license is expired
        if ($license->isExpired()) {
            return response()->json([
                'success' => false,
                'message' => 'This license has expired',
            ], 403);
        }

        // Check max activations
        if ($license->activations >= $license->max_activations) {
            // Check if this machine is already activated
            if ($license->machine_id !== $validated['machine_id']) {
                return response()->json([
                    'success' => false,
                    'message' => "Maximum activations reached ({$license->max_activations} devices). Please deactivate another device first.",
                ], 403);
            }
        }

        // Activate on this machine
        $license->activateOnMachine(
            $validated['machine_id'],
            $request->input('machine_fingerprint', $validated['machine_id'])
        );

        // Get order info for customer details
        $order = $license->order;

        return response()->json([
            'success' => true,
            'message' => 'License activated successfully',
            'data' => [
                'email' => $order?->email ?? null,
                'customer_name' => $order?->customer_name ?? null,
                'product_name' => $license->product->name,
                'expires_at' => $license->expires_at?->toISOString(),
                'max_devices' => $license->max_activations,
                'current_devices' => $license->activations,
                'features' => self::FULL_FEATURES,
                'status' => $license->status,
                'license_type' => $license->license_type,
            ],
        ]);
    }

    /**
     * Validate an existing license
     *
     * POST /api/v1/license/validate
     */
    public function validate(Request $request)
    {
        $validated = $request->validate([
            'license_key' => 'required|string',
            'machine_id' => 'required|string|size:32',
            'product_id' => 'required|string',
        ]);

        $license = LicenseKey::where('license_key', strtoupper($validated['license_key']))
            ->whereHas('product', fn($q) => $q->where('slug', $validated['product_id']))
            ->first();

        if (!$license) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid license key',
            ], 404);
        }

        // Verify machine ID matches
        if ($license->machine_id && $license->machine_id !== $validated['machine_id']) {
            return response()->json([
                'success' => false,
                'message' => 'License is activated on a different device',
            ], 403);
        }

        // Check if valid
        if (!$license->isValid()) {
            return response()->json([
                'success' => false,
                'message' => $license->isExpired() ? 'License has expired' : 'License is not valid',
            ], 403);
        }

        // Update last validated timestamp
        $license->update(['last_validated_at' => now()]);

        return response()->json([
            'success' => true,
            'message' => 'License is valid',
            'data' => [
                'expires_at' => $license->expires_at?->toISOString(),
                'features' => self::FULL_FEATURES,
                'status' => $license->status,
                'days_remaining' => $license->daysRemaining(),
            ],
        ]);
    }

    /**
     * Deactivate a license from a machine
     *
     * POST /api/v1/license/deactivate
     */
    public function deactivate(Request $request)
    {
        $validated = $request->validate([
            'license_key' => 'required|string',
            'machine_id' => 'required|string|size:32',
            'product_id' => 'required|string',
        ]);

        $license = LicenseKey::where('license_key', strtoupper($validated['license_key']))
            ->whereHas('product', fn($q) => $q->where('slug', $validated['product_id']))
            ->first();

        if (!$license) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid license key',
            ], 404);
        }

        // Verify machine ID matches
        if ($license->machine_id !== $validated['machine_id']) {
            return response()->json([
                'success' => false,
                'message' => 'License is not activated on this device',
            ], 403);
        }

        // Deactivate
        $license->update([
            'machine_id' => null,
            'device_id' => null,
            'machine_fingerprint' => null,
            'activated_at' => null,
            'activations' => max(0, $license->activations - 1),
        ]);

        return response()->json([
            'success' => true,
            'message' => 'License deactivated successfully',
        ]);
    }

    /**
     * Get license status
     *
     * GET /api/v1/license/status/{license_key}
     */
    public function status(string $licenseKey)
    {
        $license = LicenseKey::where('license_key', strtoupper($licenseKey))->first();

        if (!$license) {
            return response()->json([
                'success' => false,
                'message' => 'License not found',
            ], 404);
        }

        return response()->json([
            'success' => true,
            'data' => [
                'license_key' => $license->license_key,
                'status' => $license->status,
                'license_type' => $license->license_type,
                'expires_at' => $license->expires_at?->toISOString(),
                'activations' => $license->activations,
                'max_activations' => $license->max_activations,
                'is_valid' => $license->isValid(),
                'days_remaining' => $license->daysRemaining(),
            ],
        ]);
    }

    /**
     * Start a demo/trial period
     *
     * POST /api/v1/license/demo
     */
    public function startDemo(Request $request)
    {
        $validated = $request->validate([
            'machine_id' => 'required|string|size:32',
            'product_id' => 'required|string',
            'machine_name' => 'nullable|string|max:255',
        ]);

        // Find the product
        $product = Product::where('slug', $validated['product_id'])->first();

        if (!$product) {
            return response()->json([
                'success' => false,
                'message' => 'Product not found',
            ], 404);
        }

        // Check if this machine already has a demo
        $existingDemo = LicenseKey::where('machine_id', $validated['machine_id'])
            ->where('product_id', $product->id)
            ->where('license_type', LicenseKey::TYPE_DEMO)
            ->first();

        if ($existingDemo) {
            // Check if demo is expired
            if ($existingDemo->isExpired()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Your trial period has ended. Please purchase a license to continue using the software.',
                ], 403);
            }

            // Return existing demo
            return response()->json([
                'success' => true,
                'message' => 'Demo already active',
                'data' => [
                    'expires_at' => $existingDemo->expires_at?->toISOString(),
                    'days_remaining' => $existingDemo->daysRemaining(),
                    'features' => self::TRIAL_FEATURES,
                ],
            ]);
        }

        // Create new demo license
        $demoKey = LicenseKey::generateDemoKey();
        $demo = LicenseKey::create([
            'product_id' => $product->id,
            'license_key' => $demoKey,
            'status' => LicenseKey::STATUS_ACTIVE,
            'license_type' => LicenseKey::TYPE_DEMO,
            'machine_id' => $validated['machine_id'],
            'activated_at' => now(),
            'expires_at' => now()->addDays(7), // 7-day trial
            'max_activations' => 1,
            'activations' => 1,
            'metadata' => json_encode([
                'machine_name' => $validated['machine_name'] ?? 'Unknown',
                'started_at' => now()->toISOString(),
            ]),
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Demo started successfully',
            'data' => [
                'expires_at' => $demo->expires_at->toISOString(),
                'days_remaining' => 7,
                'features' => self::TRIAL_FEATURES,
            ],
        ]);
    }

    /**
     * Check demo status
     *
     * POST /api/v1/license/demo/check
     */
    public function checkDemo(Request $request)
    {
        $validated = $request->validate([
            'machine_id' => 'required|string|size:32',
            'product_id' => 'required|string',
        ]);

        $product = Product::where('slug', $validated['product_id'])->first();

        if (!$product) {
            return response()->json([
                'success' => false,
                'message' => 'Product not found',
            ], 404);
        }

        $demo = LicenseKey::where('machine_id', $validated['machine_id'])
            ->where('product_id', $product->id)
            ->where('license_type', LicenseKey::TYPE_DEMO)
            ->first();

        if (!$demo) {
            return response()->json([
                'success' => false,
                'message' => 'No demo found for this machine',
            ], 404);
        }

        return response()->json([
            'success' => true,
            'data' => [
                'is_valid' => $demo->isValid(),
                'is_expired' => $demo->isExpired(),
                'days_remaining' => $demo->daysRemaining(),
                'expires_at' => $demo->expires_at?->toISOString(),
                'features' => self::TRIAL_FEATURES,
            ],
        ]);
    }
}
