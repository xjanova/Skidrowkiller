<?php

namespace Database\Seeders;

use App\Models\Category;
use App\Models\Product;
use App\Models\LicenseKey;
use Illuminate\Database\Seeder;
use Illuminate\Support\Str;

/**
 * Skidrow Killer Product Seeder for XManStudio
 *
 * This seeder creates the necessary category, product, and initial license data
 * for the Skidrow Killer anti-malware software.
 *
 * Usage: php artisan db:seed --class=SkidrowKillerSeeder
 */
class SkidrowKillerSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // ============================================
        // 1. Create Category (if not exists)
        // ============================================
        $category = Category::firstOrCreate(
            ['slug' => 'security-software'],
            [
                'name' => 'Security Software',
                'slug' => 'security-software',
                'description' => 'Anti-malware, antivirus, and security protection software',
                'icon' => 'shield-check', // Heroicons or FontAwesome icon name
                'order' => 1,
                'is_active' => true,
            ]
        );

        $this->command->info("Category created: {$category->name}");

        // ============================================
        // 2. Create Product: Skidrow Killer
        // ============================================
        $product = Product::updateOrCreate(
            ['slug' => 'skidrow-killer'],
            [
                'category_id' => $category->id,
                'name' => 'Skidrow Killer',
                'slug' => 'skidrow-killer',
                'description' => $this->getFullDescription(),
                'short_description' => 'Advanced malware scanner with real-time protection, behavioral analysis, and smart threat detection. Protect your PC from Skidrow cracks, trojans, and malicious software.',
                'features' => $this->getFeatures(),
                'price' => 299.00, // Base price (Yearly)
                'image' => 'products/skidrow-killer/logo.png',
                'images' => [
                    'products/skidrow-killer/screenshot-1.png',
                    'products/skidrow-killer/screenshot-2.png',
                    'products/skidrow-killer/screenshot-3.png',
                ],
                'sku' => 'SKD-KILLER-001',
                'is_custom' => false,
                'requires_license' => true,
                'stock' => 9999, // Digital product, unlimited
                'low_stock_threshold' => 0,
                'is_active' => true,
            ]
        );

        $this->command->info("Product created: {$product->name} (ID: {$product->id})");

        // ============================================
        // 3. Create Pricing Variants (using metadata or separate table)
        // ============================================
        // Note: XManStudio may handle pricing variants differently
        // This is the recommended pricing structure:
        $pricingInfo = [
            'monthly' => [
                'price' => 49.00,
                'currency' => 'THB',
                'duration_days' => 30,
                'license_type' => LicenseKey::TYPE_MONTHLY,
            ],
            'yearly' => [
                'price' => 299.00,
                'currency' => 'THB',
                'duration_days' => 365,
                'license_type' => LicenseKey::TYPE_YEARLY,
                'savings' => '50%', // Save 50% compared to monthly
            ],
            'lifetime' => [
                'price' => 599.00,
                'currency' => 'THB',
                'duration_days' => null, // Forever
                'license_type' => LicenseKey::TYPE_LIFETIME,
                'savings' => 'Best Value',
            ],
        ];

        $this->command->info("Pricing structure:");
        foreach ($pricingInfo as $type => $info) {
            $this->command->info("  - {$type}: {$info['price']} {$info['currency']}");
        }

        // ============================================
        // 4. Create Demo License Keys (for testing)
        // ============================================
        $demoKeys = [
            'DEMO-TEST-0001-XXXX',
            'DEMO-TEST-0002-XXXX',
            'DEMO-TRIAL-001-XXXX',
        ];

        foreach ($demoKeys as $key) {
            LicenseKey::firstOrCreate(
                ['license_key' => $key],
                [
                    'product_id' => $product->id,
                    'order_id' => null, // Demo keys don't have orders
                    'license_key' => $key,
                    'status' => LicenseKey::STATUS_ACTIVE,
                    'license_type' => LicenseKey::TYPE_DEMO,
                    'activated_at' => null,
                    'expires_at' => now()->addDays(7), // 7-day demo
                    'max_activations' => 1,
                    'activations' => 0,
                    'metadata' => json_encode([
                        'is_test_key' => true,
                        'created_by' => 'seeder',
                    ]),
                ]
            );
        }

        $this->command->info("Demo license keys created: " . count($demoKeys));

        // ============================================
        // 5. Product Configuration (for API)
        // ============================================
        $this->command->newLine();
        $this->command->info("=== Product Configuration for Client App ===");
        $this->command->info("Product ID: skidrow-killer");
        $this->command->info("API Base URL: https://xmanstudio.com/api/v1");
        $this->command->newLine();
        $this->command->info("API Endpoints:");
        $this->command->info("  POST /license/activate    - Activate license");
        $this->command->info("  POST /license/validate    - Validate license");
        $this->command->info("  POST /license/deactivate  - Deactivate license");
        $this->command->info("  POST /license/demo        - Start demo/trial");
        $this->command->info("  GET  /license/demo/check  - Check demo status");
        $this->command->info("  GET  /updates/{product}/check - Check for updates");
        $this->command->newLine();
        $this->command->info("License Types:");
        $this->command->info("  - demo: 7 days trial");
        $this->command->info("  - monthly: 30 days");
        $this->command->info("  - yearly: 365 days");
        $this->command->info("  - lifetime: Forever");
        $this->command->newLine();
        $this->command->info("Max Activations: 3 devices per license");
        $this->command->info("Offline Grace Period: 1 day (auto-downgrade to trial)");
    }

    /**
     * Get full product description (HTML supported)
     */
    private function getFullDescription(): string
    {
        return <<<'HTML'
<h2>Skidrow Killer - Advanced Malware Protection</h2>

<p>Skidrow Killer is a powerful anti-malware solution designed specifically to detect and remove threats commonly found in cracked software, game cracks, and pirated applications. Our advanced behavioral analysis engine can identify malicious code that traditional antivirus software often misses.</p>

<h3>Why Choose Skidrow Killer?</h3>

<ul>
    <li><strong>Real-time Protection</strong> - Continuously monitors your system for threats</li>
    <li><strong>Behavioral Analysis</strong> - Detects malware by analyzing behavior, not just signatures</li>
    <li><strong>Registry Monitoring</strong> - Watches for suspicious registry modifications</li>
    <li><strong>Network Protection</strong> - Blocks connections to known malicious servers</li>
    <li><strong>Process Injection Detection</strong> - Identifies attempts to inject code into legitimate processes</li>
    <li><strong>Smart Quarantine</strong> - Safely isolates threats without deleting important files</li>
</ul>

<h3>Key Features</h3>

<p><strong>Deep Scan Technology</strong><br>
Our proprietary scanning engine analyzes files at multiple levels - from basic signature matching to advanced heuristic analysis and behavioral pattern recognition.</p>

<p><strong>Lightweight Performance</strong><br>
Designed to run efficiently in the background without impacting system performance. Uses minimal CPU and memory resources.</p>

<p><strong>Automatic Updates</strong><br>
Threat definitions and software updates are delivered automatically to ensure you're always protected against the latest threats.</p>

<h3>System Requirements</h3>

<ul>
    <li>Windows 10/11 (64-bit)</li>
    <li>.NET 8.0 Runtime</li>
    <li>4 GB RAM minimum</li>
    <li>100 MB disk space</li>
    <li>Internet connection for updates</li>
</ul>
HTML;
    }

    /**
     * Get product features array
     */
    private function getFeatures(): array
    {
        return [
            [
                'icon' => 'shield-check',
                'title' => 'Real-time Protection',
                'description' => 'Continuous monitoring and instant threat blocking',
            ],
            [
                'icon' => 'cpu-chip',
                'title' => 'Behavioral Analysis',
                'description' => 'AI-powered detection of suspicious behaviors',
            ],
            [
                'icon' => 'document-magnifying-glass',
                'title' => 'Deep Scan',
                'description' => 'Multi-level file analysis with heuristics',
            ],
            [
                'icon' => 'server-stack',
                'title' => 'Registry Monitoring',
                'description' => 'Watches for malicious registry changes',
            ],
            [
                'icon' => 'globe-alt',
                'title' => 'Network Protection',
                'description' => 'Blocks C2 servers and malicious connections',
            ],
            [
                'icon' => 'archive-box',
                'title' => 'Smart Quarantine',
                'description' => 'Safe isolation with easy restoration',
            ],
            [
                'icon' => 'arrow-path',
                'title' => 'Auto Updates',
                'description' => 'Automatic threat definition updates',
            ],
            [
                'icon' => 'bolt',
                'title' => 'Lightweight',
                'description' => 'Minimal system resource usage',
            ],
        ];
    }
}
