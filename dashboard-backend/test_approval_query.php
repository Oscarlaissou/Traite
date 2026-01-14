<?php
// Script de test pour la requête d'historique d'approbation

require_once __DIR__ . '/vendor/autoload.php';

use Illuminate\Support\Facades\DB;
use Illuminate\Foundation\Application;

// Charger l'application Laravel
$app = require_once __DIR__ . '/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

$userId = 8; // L'ID de l'utilisateur que nous voulons tester

echo "=== Test de la requête pour l'utilisateur ID: $userId ===\n\n";

try {
    // Exécuter la même requête que dans le contrôleur (version corrigée)
    $history = DB::table('client_approvals as ca')
        ->select(
            'ca.id',
            'ca.tier_id as client_id',
            'ca.status',
            'ca.rejection_reason',
            'ca.created_at',
            DB::raw('CASE 
                WHEN ca.status = "approved" THEN COALESCE((SELECT t.nom_raison_sociale FROM tiers t WHERE t.id = ca.tier_id), "Client approuvé")
                WHEN ca.status = "rejected" THEN COALESCE((SELECT pc.nom_raison_sociale FROM pending_clients pc WHERE pc.id = ca.tier_id), "Client rejeté")
                WHEN ca.status = "pending" THEN COALESCE((SELECT pc.nom_raison_sociale FROM pending_clients pc WHERE pc.id = ca.tier_id), (SELECT t.nom_raison_sociale FROM tiers t WHERE t.id = ca.tier_id), "Client en attente")
                ELSE "Inconnu"
            END as client_name'),
            DB::raw('CASE 
                WHEN ca.status = "approved" THEN COALESCE((SELECT t.numero_compte FROM tiers t WHERE t.id = ca.tier_id), "N/A")
                WHEN ca.status = "rejected" THEN COALESCE((SELECT pc.numero_compte FROM pending_clients pc WHERE pc.id = ca.tier_id), "N/A")
                WHEN ca.status = "pending" THEN COALESCE((SELECT pc.numero_compte FROM pending_clients pc WHERE pc.id = ca.tier_id), (SELECT t.numero_compte FROM tiers t WHERE t.id = ca.tier_id), "N/A")
                ELSE "N/A"
            END as account_number')
        )
        ->where('ca.user_id', $userId)
        ->orderBy('ca.created_at', 'desc')
        ->get();
    
    echo "Résultats bruts de la requête:\n";
    echo "Nombre d'enregistrements trouvés: " . count($history) . "\n\n";
    
    foreach ($history as $record) {
        echo "ID: {$record->id}\n";
        echo "Client ID: {$record->client_id}\n";
        echo "Status: {$record->status}\n";
        echo "Client Name: " . ($record->client_name ?? 'NULL') . "\n";
        echo "Account Number: " . ($record->account_number ?? 'NULL') . "\n";
        echo "Created At: {$record->created_at}\n";
        echo "Rejection Reason: " . ($record->rejection_reason ?? 'NULL') . "\n";
        echo "---\n";
    }
    
    // Vérifions aussi les données dans les tables associées
    echo "\n=== Données dans la table tiers pour les tier_id concernés ===\n";
    $clientIds = collect($history)->pluck('client_id')->unique()->toArray();
    if (!empty($clientIds)) {
        $tiersData = DB::table('tiers')->whereIn('id', $clientIds)->get();
        foreach ($tiersData as $tier) {
            echo "Tier ID: {$tier->id}\n";
            echo "Nom: {$tier->nom_raison_sociale}\n";
            echo "Numéro de compte: {$tier->numero_compte}\n";
            echo "---\n";
        }
    } else {
        echo "Aucun tier_id trouvé dans les résultats.\n";
    }
    
    echo "\n=== Données dans la table pending_clients ===\n";
    $pendingData = DB::table('pending_clients')->get();
    echo "Nombre total de clients en attente: " . count($pendingData) . "\n";
    
} catch (Exception $e) {
    echo "Erreur lors de l'exécution de la requête:\n";
    echo "Message: " . $e->getMessage() . "\n";
    echo "Fichier: " . $e->getFile() . "\n";
    echo "Ligne: " . $e->getLine() . "\n";
}