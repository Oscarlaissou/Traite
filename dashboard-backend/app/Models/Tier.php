<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

/**
 * Modèle Eloquent pour la table des tiers (clients).
 */
class Tier extends Model
{
    use HasFactory;

    /**
     * Définition explicite du nom de la table cible.
     */
    protected $table = 'tiers';

    /**
     * La table tiers ne contient pas les colonnes created_at / updated_at par défaut.
     * Mais nous pouvons les activer si elles existent dans la base de données.
     */
    public $timestamps = false;

    /**
     * Aucune protection sur les attributs afin de permettre les remplissages massifs contrôlés.
     */
    protected $guarded = [];

    /**
     * Casting basique des attributs temporels.
     */
    protected $casts = [
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];
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
    ];

    /**
     * Relation avec les activités du tier.
     */
    public function activities()
    {
        return $this->hasMany(TierActivity::class);
    }

    /**
     * Relation avec la dernière activité du tier.
     */
    public function latestActivity()
    {
        return $this->hasOne(TierActivity::class)->latestOfMany();
    }
    
    /**
     * Accesseur pour created_at - retourne la vraie date de création du client.
     */
    public function getCreatedAtAttribute($value)
    {
        // Si la colonne created_at existe dans la base de données et a une valeur, la retourner
        if ($value !== null) {
            return $value;
        }
        
        // Sinon, essayer de trouver la première activité pour déterminer la date de création
        $firstActivity = $this->activities()->oldest()->first();
        if ($firstActivity && $firstActivity->created_at) {
            return $firstActivity->created_at;
        }
        
        // Si aucune activité n'existe, retourner null (pas de date de création disponible)
        return null;
    }
    
    /**
     * Accesseur pour updated_at - retourne la date de mise à jour du client.
     */
    public function getUpdatedAtAttribute($value)
    {
        // Si la colonne updated_at existe dans la base de données et a une valeur, la retourner
        if ($value !== null) {
            return $value;
        }
        
        // Sinon, utiliser la date de création ou la dernière activité
        $latestActivity = $this->activities()->latest()->first();
        if ($latestActivity && $latestActivity->created_at) {
            return $latestActivity->created_at;
        }
        
        // Fallback sur la date de création
        return $this->created_at;
    }
}