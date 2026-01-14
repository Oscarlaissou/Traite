<?php
// Simple script to test the API endpoint
$url = 'http://localhost:8000/api/clients/approval-history';

// Initialize cURL
$ch = curl_init($url);

// Set cURL options
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Accept: application/json',
    'Authorization: Bearer your-test-token-here' // You'll need a real token
]);

// Execute the request
$response = curl_exec($ch);

// Get HTTP status code
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

// Close cURL
curl_close($ch);

echo "HTTP Status Code: " . $httpCode . "\n";
echo "Response:\n" . $response . "\n";