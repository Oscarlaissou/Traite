<?php
// Simple script to check if there's data in the client_approvals table

require_once 'vendor/autoload.php';
require_once 'bootstrap/app.php';

use Illuminate\Support\Facades\DB;

try {
    $approvals = DB::table('client_approvals')->get();
    
    echo "Total approvals in table: " . count($approvals) . "\n";
    
    foreach ($approvals as $approval) {
        echo "ID: {$approval->id}, Client ID: {$approval->client_id}, Status: {$approval->status}, Created by: {$approval->created_by}\n";
    }
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}