<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\Traite;
use App\Models\TraiteActivity;

class CreateMissingActivities extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'activities:create-missing';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create missing activities for existing traites';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $this->info('=== CRÉATION DES ACTIVITÉS MANQUANTES ===');

        $traites = Traite::all();
        $created = 0;
        $skipped = 0;

        $bar = $this->output->createProgressBar($traites->count());
        $bar->start();

        foreach ($traites as $traite) {
            // Vérifier si une activité existe déjà pour cette traite
            $existingActivity = TraiteActivity::where('traite_id', $traite->id)->first();
            
            if (!$existingActivity) {
                // Créer une activité de "Création" pour les traites existantes
                TraiteActivity::create([
                    'traite_id' => $traite->id,
                    'user_id' => null, // Pas d'utilisateur pour les traites existantes
                    'action' => 'Création',
                    'changes' => null,
                    'created_at' => $traite->created_at, // Utiliser la date de création de la traite
                    'updated_at' => $traite->created_at,
                ]);
                $created++;
            } else {
                $skipped++;
            }
            
            $bar->advance();
        }

        $bar->finish();
        $this->newLine();

        $this->info('=== RÉSUMÉ ===');
        $this->line("Activités créées: {$created}");
        $this->line("Activités ignorées (déjà existantes): {$skipped}");
        $this->line("Total traites: " . $traites->count());

        // Vérifier le résultat
        $totalActivities = TraiteActivity::count();
        $this->line("Total activités en base: {$totalActivities}");

        $this->newLine();
        $this->info('=== VÉRIFICATION ===');
        $traitesWithoutActivity = Traite::whereDoesntHave('activities')->count();
        $this->line("Traites sans activité: {$traitesWithoutActivity}");

        if ($traitesWithoutActivity === 0) {
            $this->info('✅ Toutes les traites ont maintenant une activité !');
        } else {
            $this->error("❌ Il reste {$traitesWithoutActivity} traites sans activité.");
        }

        return Command::SUCCESS;
    }
}