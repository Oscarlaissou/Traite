<?php
// Script pour sélectionner et afficher les données de la table client_approvals

require_once __DIR__ . '/vendor/autoload.php';

use Illuminate\Support\Facades\DB;
use Illuminate\Foundation\Application;

// Charger l'application Laravel
$app = require_once __DIR__ . '/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

try {
    echo "=== Requête SELECT sur la table client_approvals ===\n\n";
    
    // Exécuter une requête SELECT simple sur la table client_approvals
    $results = DB::select('SELECT * FROM client_approvals');
    
    if (empty($results)) {
        echo "Aucun résultat trouvé dans la table client_approvals.\n";
        echo "La table est vide ou n'existe pas.\n";
    } else {
        echo "Nombre de résultats trouvés: " . count($results) . "\n\n";
        
        // Afficher les en-têtes
        echo str_pad("ID", 5) . " | " . 
             str_pad("client_id", 12) . " | " . 
             str_pad("created_by", 12) . " | " . 
             str_pad("status", 10) . " | " . 
             str_pad("rejection_reason", 20) . " | " . 
             "created_at\n";
        echo str_repeat("-", 100) . "\n";
        
        // Afficher chaque ligne de résultat
        foreach ($results as $row) {
            echo str_pad($row->id, 5) . " | " . 
                 str_pad($row->client_id, 12) . " | " . 
                 str_pad($row->created_by, 12) . " | " . 
                 str_pad($row->status, 10) . " | " . 
                 str_pad(substr($row->rejection_reason ?? 'N/A', 0, 18), 20) . " | " . 
                 $row->created_at . "\n";
        }
    }
    
    echo "\n=== Informations supplémentaires ===\n";
    
    // Compter le nombre total d'enregistrements
    $totalCount = DB::table('client_approvals')->count();
    echo "Nombre total d'enregistrements (via Query Builder): $totalCount\n";
    
    // Compter les enregistrements par statut
    $approvedCount = DB::table('client_approvals')->where('status', 'approved')->count();
    $rejectedCount = DB::table('client_approvals')->where('status', 'rejected')->count();
    
    echo "Clients approuvés: $approvedCount\n";
    echo "Clients rejetés: $rejectedCount\n";
    
} catch (Exception $e) {
    echo "Erreur lors de l'exécution de la requête:\n";
    echo "Message: " . $e->getMessage() . "\n";
    echo "Fichier: " . $e->getFile() . "\n";
    echo "Ligne: " . $e->getLine() . "\n";
}