<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Product;
use App\Models\LicenseKey;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Carbon\Carbon;

/**
 * Update Controller for Skidrow Killer
 *
 * Handles software update checks and download authorization
 */
class UpdateController extends Controller
{
    /**
     * Check for software updates
     *
     * GET /api/v1/updates/{product_id}/check
     */
    public function check(Request $request, string $productId)
    {
        $product = Product::where('slug', $productId)->first();

        if (!$product) {
            return response()->json([
                'success' => false,
                'message' => 'Product not found',
            ], 404);
        }

        // Get latest release from metadata or releases table
        // This is an example - adjust based on your actual data structure
        $latestRelease = $this->getLatestRelease($product);

        if (!$latestRelease) {
            return response()->json([
                'update_available' => false,
                'message' => 'No updates available',
            ]);
        }

        // Check if user is licensed (for priority updates)
        $licenseKey = $request->header('X-License-Key');
        $isLicensed = false;

        if ($licenseKey) {
            $license = LicenseKey::where('license_key', strtoupper($licenseKey))
                ->where('product_id', $product->id)
                ->first();

            $isLicensed = $license?->isValid() ?? false;
        }

        return response()->json([
            'update_available' => true,
            'latest_version' => $latestRelease['version'],
            'release_notes' => $latestRelease['release_notes'],
            'download_url' => $isLicensed
                ? $latestRelease['direct_download_url']
                : $latestRelease['public_download_url'],
            'release_url' => $latestRelease['release_url'],
            'published_at' => $latestRelease['published_at'],
            'is_pre_release' => $latestRelease['is_pre_release'] ?? false,
            'requires_license' => $latestRelease['requires_license'] ?? false,
            'file_size' => $latestRelease['file_size'] ?? null,
            'checksum' => $latestRelease['checksum'] ?? null,
        ]);
    }

    /**
     * Get authorized download URL for licensed users
     *
     * POST /api/v1/updates/{product_id}/download
     */
    public function getDownloadUrl(Request $request, string $productId)
    {
        $licenseKey = $request->header('X-License-Key');

        if (!$licenseKey) {
            return response()->json([
                'success' => false,
                'message' => 'License key required',
            ], 401);
        }

        $product = Product::where('slug', $productId)->first();

        if (!$product) {
            return response()->json([
                'success' => false,
                'message' => 'Product not found',
            ], 404);
        }

        $license = LicenseKey::where('license_key', strtoupper($licenseKey))
            ->where('product_id', $product->id)
            ->first();

        if (!$license || !$license->isValid()) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid or expired license',
            ], 403);
        }

        // Generate a temporary signed download URL
        $latestRelease = $this->getLatestRelease($product);

        if (!$latestRelease) {
            return response()->json([
                'success' => false,
                'message' => 'No download available',
            ], 404);
        }

        // Create a signed URL that expires in 1 hour
        $signedUrl = $this->generateSignedDownloadUrl($product, $latestRelease, $license);

        return response()->json([
            'success' => true,
            'download_url' => $signedUrl,
            'expires_at' => now()->addHour()->toISOString(),
            'file_name' => $latestRelease['file_name'] ?? "SkidrowKiller-{$latestRelease['version']}.exe",
            'file_size' => $latestRelease['file_size'] ?? null,
            'checksum' => $latestRelease['checksum'] ?? null,
        ]);
    }

    /**
     * Get latest release info for a product
     * Adjust this method based on your actual data structure
     */
    private function getLatestRelease(Product $product): ?array
    {
        // Option 1: From product metadata
        $metadata = is_array($product->metadata)
            ? $product->metadata
            : json_decode($product->metadata ?? '{}', true);

        if (isset($metadata['latest_release'])) {
            return $metadata['latest_release'];
        }

        // Option 2: From a releases table (if you have one)
        // $release = $product->releases()->latest()->first();
        // if ($release) {
        //     return [
        //         'version' => $release->version,
        //         'release_notes' => $release->notes,
        //         'direct_download_url' => $release->download_url,
        //         'public_download_url' => route('products.show', $product),
        //         'release_url' => route('releases.show', $release),
        //         'published_at' => $release->published_at->toISOString(),
        //         'is_pre_release' => $release->is_pre_release,
        //         'requires_license' => true,
        //         'file_size' => $release->file_size,
        //         'checksum' => $release->checksum,
        //     ];
        // }

        // Default return structure for demo/development
        return [
            'version' => '1.0.0',
            'release_notes' => 'Initial release',
            'direct_download_url' => config('app.url') . '/downloads/' . $product->slug . '/latest',
            'public_download_url' => config('app.url') . '/products/' . $product->slug,
            'release_url' => config('app.url') . '/products/' . $product->slug . '/releases/1.0.0',
            'published_at' => now()->toISOString(),
            'is_pre_release' => false,
            'requires_license' => false,
            'file_name' => 'SkidrowKiller-1.0.0.exe',
            'file_size' => null,
            'checksum' => null,
        ];
    }

    /**
     * Generate a signed download URL
     */
    private function generateSignedDownloadUrl(Product $product, array $release, LicenseKey $license): string
    {
        // Option 1: Use Laravel's signed URLs
        return url()->temporarySignedRoute(
            'downloads.serve',
            now()->addHour(),
            [
                'product' => $product->slug,
                'version' => $release['version'],
                'license' => substr($license->license_key, 0, 8),
            ]
        );

        // Option 2: If using S3/cloud storage
        // return Storage::disk('s3')->temporaryUrl(
        //     "releases/{$product->slug}/{$release['version']}/installer.exe",
        //     now()->addHour()
        // );
    }
}
