# Skidrow Killer - XManStudio Integration

This folder contains seed files and API controllers for integrating Skidrow Killer with XManStudio.

## Files

| File | Description |
|------|-------------|
| `SkidrowKillerSeeder.php` | Database seeder for Category, Product, and demo License keys |
| `LicenseController.php` | API controller for license management |
| `UpdateController.php` | API controller for software updates |
| `api_routes.php` | API route definitions |

## Installation

### 1. Copy Seeder

```bash
cp seeds/SkidrowKillerSeeder.php /path/to/xmanstudio/database/seeders/
```

### 2. Copy Controllers

```bash
cp seeds/LicenseController.php /path/to/xmanstudio/app/Http/Controllers/Api/
cp seeds/UpdateController.php /path/to/xmanstudio/app/Http/Controllers/Api/
```

### 3. Add Routes

Add to `routes/api.php`:

```php
require __DIR__ . '/../seeds/api_routes.php';
```

Or copy the route definitions directly into your `routes/api.php`.

### 4. Run Seeder

```bash
php artisan db:seed --class=SkidrowKillerSeeder
```

## Product Configuration

| Setting | Value |
|---------|-------|
| Product ID | `skidrow-killer` |
| SKU | `SKD-KILLER-001` |
| Category | Security Software |

## Pricing Structure (Editable via Admin)

| Plan | Price (THB) | Duration |
|------|-------------|----------|
| Monthly | 49.00 | 30 days |
| Yearly | 299.00 | 365 days |
| Lifetime | 599.00 | Forever |

## License Configuration

| Setting | Value |
|---------|-------|
| Max Activations | 3 devices |
| Trial Period | 7 days |
| Offline Grace Period | 24 hours |

## API Endpoints

### License Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/license/ping` | Health check |
| POST | `/api/v1/license/activate` | Activate license |
| POST | `/api/v1/license/validate` | Validate license |
| POST | `/api/v1/license/deactivate` | Deactivate license |
| GET | `/api/v1/license/status/{key}` | Get license status |
| POST | `/api/v1/license/demo` | Start trial |
| POST | `/api/v1/license/demo/check` | Check trial status |

### Updates

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/updates/{product}/check` | Check for updates |
| POST | `/api/v1/updates/{product}/download` | Get download URL |

## Features by License Type

### Trial Features
- `basic_scan`
- `real_time_protection`

### Full License Features
- `basic_scan`
- `full_scan`
- `deep_scan`
- `real_time_protection`
- `behavioral_analysis`
- `registry_monitoring`
- `network_protection`
- `process_injection_detection`
- `auto_quarantine`
- `scheduled_scans`
- `priority_updates`
- `email_support`

## Client Configuration

The Skidrow Killer application is pre-configured with:

```csharp
API_BASE_URL = "https://xmanstudio.com/api/v1/license"
PRODUCT_ID = "skidrow-killer"
OFFLINE_GRACE_PERIOD = 24 hours
MAX_ACTIVATIONS = 3
TRIAL_DAYS = 7
```

## Offline Behavior

1. Application checks connectivity every 30 minutes
2. If offline for more than 24 hours, license auto-downgrades to Trial
3. When back online, license automatically restores if still valid
4. Trial features are limited to basic scanning and real-time protection

## Security Notes

- Machine ID is generated from CPU + Motherboard + BIOS serial numbers (SHA256 hash)
- License data is encrypted locally using AES-256
- All API requests include User-Agent and Product-ID headers
- License validation uses machine fingerprint verification
