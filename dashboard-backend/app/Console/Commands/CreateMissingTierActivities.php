<?php

namespace App\Console\Commands;

use App\Models\Tier;
use App\Models\TierActivity;
use Illuminate\Console\Command;

class CreateMissingTierActivities extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'tiers:create-missing-activities';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Crée les activités manquantes pour les tiers existants';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $this->info('Création des activités manquantes pour les tiers...');

        $tiers = Tier::all();
        $created = 0;

        foreach ($tiers as $tier) {
            // Vérifier si une activité existe déjà pour ce tier
            $hasActivity = TierActivity::where('tier_id', $tier->id)->exists();

            if (!$hasActivity) {
                TierActivity::create([
                    'tier_id' => $tier->id,
                    'user_id' => null, // Pas d'utilisateur pour les anciens enregistrements
                    'action' => 'Création',
                    'changes' => $tier->only([
                        'numero_compte', 'nom_raison_sociale', 'bp', 'ville', 'pays',
                        'adresse_geo_1', 'adresse_geo_2', 'telephone', 'email',
                        'categorie', 'n_contribuable', 'type_tiers'
                    ]),
                ]);
                $created++;
            }
        }

        $this->info("$created activités créées avec succès.");
        return 0;
    }
}
