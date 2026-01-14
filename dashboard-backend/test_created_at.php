<?php
require_once 'vendor/autoload.php';

use Illuminate\Support\Facades\Schema;

$app = require_once 'bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Console\Kernel::class);
$kernel->bootstrap();

// Test si la colonne created_at existe dans la table tiers
$hasCreatedAt = Schema::hasColumn('tiers', 'created_at');
echo "La colonne 'created_at' existe dans la table 'tiers': " . ($hasCreatedAt ? 'Oui' : 'Non') . "\n";

// Test avec un modèle Tier
$tier = App\Models\Tier::first();
if ($tier) {
    echo "Premier client trouvé: " . $tier->nom_raison_sociale . "\n";
    echo "created_at: " . json_encode($tier->created_at) . "\n";
} else {
    echo "Aucun client trouvé.\n";
}