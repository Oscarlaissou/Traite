<?php
require_once 'vendor/autoload.php';

use Illuminate\Container\Container;
use Illuminate\Database\Capsule\Manager as Capsule;

// Create a service container
$container = new Container();

// Create a Capsule instance
$capsule = new Capsule($container);
$capsule->addConnection([
    'driver'    => 'mysql',
    'host'      => '127.0.0.1',
    'database'  => 'traite',
    'username'  => 'root',
    'password'  => '',
    'charset'   => 'utf8',
    'collation' => 'utf8_unicode_ci',
    'prefix'    => '',
]);

$capsule->setAsGlobal();
$capsule->bootEloquent();

try {
    $columns = Capsule::select('SHOW COLUMNS FROM client_approvals');
    echo "Actual columns in client_approvals table:\n";
    foreach ($columns as $column) {
        echo "- {$column->Field} ({$column->Type})\n";
    }
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}