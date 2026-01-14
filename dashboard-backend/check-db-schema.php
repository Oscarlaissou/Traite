<?php

require_once 'vendor/autoload.php';

// Bootstrap Laravel
$app = require_once 'bootstrap/app.php';

// Make the app handle the request
$kernel = $app->make(Illuminate\Contracts\Console\Kernel::class);
$kernel->bootstrap();

// Check database schema
try {
    $columns = \DB::select('DESCRIBE organization_settings');
    echo "Organization settings table structure:\n";
    foreach ($columns as $column) {
        echo "- {$column->Field} ({$column->Type})\n";
    }
} catch (Exception $e) {
    echo "Error checking database schema: " . $e->getMessage() . "\n";
}