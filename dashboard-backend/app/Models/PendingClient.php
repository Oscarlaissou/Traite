<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class PendingClient extends Model
{
    use HasFactory;

    protected $fillable = [
        'numero_compte',
        'nom_raison_sociale',
        'bp',
        'ville',
        'pays',
        'adresse_geo_1',
        'adresse_geo_2',
        'telephone',
        'email',
        'categorie',
        'n_contribuable',
        'type_tiers',
        'date_creation',
        'montant_facture',
        'montant_paye',
        'credit',
        'motif',
        'etablissement',
        'service',
        'nom_signataire',
        'created_by',
        'status'
    ];

    protected $casts = [
        'date_creation' => 'date',
        'montant_facture' => 'decimal:2',
        'montant_paye' => 'decimal:2',
        'credit' => 'decimal:2'
    ];

    // Générer automatiquement le numéro de compte avant la création
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($client) {
            // Générer un numéro de compte séquentiel si aucun n'est fourni
            if (empty($client->numero_compte)) {
                $client->numero_compte = static::generateSequentialAccountNumber();
            }
        });
    }

    // Méthode pour générer un numéro de compte séquentiel simple (0001, 0002, etc.)
    public static function generateSequentialAccountNumber()
    {
        // Obtenir le dernier numéro de compte de la table tiers
        $lastTier = \App\Models\Tier::orderBy('id', 'desc')->first();
        
        // Obtenir le dernier numéro de compte attribué parmi les clients en attente (pending, approved, ou rejected)
        // On récupère tous les numéros de compte existants dans la table pending_clients
        $maxPendingNumber = static::max('numero_compte');
        
        // Déterminer le dernier ID utilisé
        $lastId = 0;
        if ($lastTier && $lastTier->numero_compte) {
            // Essayer d'extraire le numéro du compte existant
            $tierNumber = intval($lastTier->numero_compte);
            if ($tierNumber > 0) {
                $lastId = max($lastId, $tierNumber);
            }
        }
        
        if ($maxPendingNumber) {
            // Essayer d'extraire le numéro du compte existant
            $pendingNumber = intval($maxPendingNumber);
            if ($pendingNumber > 0) {
                $lastId = max($lastId, $pendingNumber);
            }
        }
        
        // Incrémenter pour obtenir le prochain numéro
        $nextId = $lastId + 1;
        
        // Formater le numéro de compte avec un padding de 4 chiffres (0001, 0002, etc.)
        $numero = str_pad($nextId, 4, '0', STR_PAD_LEFT);
        
        // Vérifier si ce numéro existe déjà dans les deux tables
        $attempts = 0;
        $maxAttempts = 10; // Limiter les tentatives pour éviter une boucle infinie
        
        while ($attempts < $maxAttempts) {
            $existsInTiers = \App\Models\Tier::where('numero_compte', $numero)->exists();
            $existsInPending = static::where('numero_compte', $numero)->exists();
            
            if (!$existsInTiers && !$existsInPending) {
                // Numéro disponible, on peut l'utiliser
                break;
            }
            
            // Numéro déjà utilisé, on passe au suivant
            $nextId++;
            $numero = str_pad($nextId, 4, '0', STR_PAD_LEFT);
            $attempts++;
        }
        
        return $numero;
    }

    // Relation avec l'utilisateur qui a créé le client
    public function createdBy()
    {
        return $this->belongsTo(User::class, 'created_by');
    }
}