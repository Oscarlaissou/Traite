<?php

require_once 'vendor/autoload.php';

// Bootstrap Laravel
$app = require_once 'bootstrap/app.php';

// Make the app handle the request
$kernel = $app->make(Illuminate\Contracts\Console\Kernel::class);
$kernel->bootstrap();

// Test organization settings
try {
    echo "Checking organization settings...\n";
    
    $setting = \App\Models\OrganizationSetting::first();
    
    if ($setting) {
        echo "Found organization setting:\n";
        echo "ID: " . $setting->id . "\n";
        echo "Name: " . $setting->name . "\n";
        echo "Logo: " . $setting->logo . "\n";
        echo "Created At: " . $setting->created_at . "\n";
        echo "Updated At: " . $setting->updated_at . "\n";
    } else {
        echo "No organization setting found.\n";
    }
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}