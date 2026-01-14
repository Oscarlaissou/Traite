<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use App\Models\Tier;
use Carbon\Carbon;

class ClientStatsController extends Controller
{
    /**
     * Fournit les statistiques de base : total, nouveaux du jour, nouveaux du mois.
     */
    public function stats(Request $request)
    {
        try {
            $now = Carbon::now();
            $today = $now->toDateString();
            $monthStart = $now->copy()->startOfMonth()->toDateString();
            $monthEnd = $now->copy()->endOfMonth()->toDateString();

            $total = Tier::query()->count();
            
            // Essayer d'abord d'utiliser la table demande_ouverture_compte
            try {
                // Comptes sur la date de création de la table demande_ouverture_compte pour le jour en cours
                $perDay = DB::table('demande_ouverture_compte')
                    ->whereDate('date_creation', $today)
                    ->count();
                    
                // Comptes sur la date de création de la table demande_ouverture_compte pour le mois en cours
                $perMonth = DB::table('demande_ouverture_compte')
                    ->whereBetween('date_creation', [$monthStart, $monthEnd])
                    ->count();
            } catch (\Exception $e) {
                // Si la table n'existe pas ou n'est pas accessible, utiliser la table tiers
                $perDay = Tier::query()
                    ->whereDate('created_at', $today)
                    ->count();
                    
                $perMonth = Tier::query()
                    ->whereBetween('created_at', [$monthStart, $monthEnd])
                    ->count();
            }

            // Vérifier si la colonne credit existe avant de l'utiliser
            $totalCredit = 0;
            if (Schema::hasColumn('tiers', 'credit')) {
                $totalCredit = (float) Tier::sum('credit');
            }
            
            return response()->json([
                'total' => $total,
                'perDay' => $perDay,
                'perMonth' => $perMonth,
                'totalCredit' => $totalCredit,
            ]);
        } catch (\Throwable $e) {
            return response()->json([
                'total' => 0,
                'perDay' => 0,
                'perMonth' => 0,
                'totalCredit' => 0,
                'error' => 'Impossible de calculer les statistiques : ' . $e->getMessage(),
            ], 200);
        }
    }

    /**
     * Fournit les données mensuelles groupées par année.
     */
    public function monthly(Request $request)
    {
        try {
            $year = (int) $request->get('year', Carbon::now()->year);
            
            // Essayer d'abord d'utiliser la table demande_ouverture_compte
            try {
                $rows = DB::table('demande_ouverture_compte')
                    ->selectRaw("DATE_FORMAT(date_creation, '%Y-%m') as ym, COUNT(*) as total")
                    ->whereYear('date_creation', $year)
                    ->groupBy('ym')
                    ->get();
            } catch (\Exception $e) {
                // Si la table n'existe pas ou n'est pas accessible, utiliser la table tiers
                $rows = Tier::query()
                    ->selectRaw("DATE_FORMAT(created_at, '%Y-%m') as ym, COUNT(*) as total")
                    ->whereYear('created_at', $year)
                    ->groupBy('ym')
                    ->get();
            }
            
            // Créer un tableau avec tous les mois de l'année (même ceux sans données)
            $months = [];
            for ($i = 1; $i <= 12; $i++) {
                $monthKey = sprintf('%04d-%02d', $year, $i);
                $months[$monthKey] = 0;
            }
            
            // Remplir avec les données existantes
            foreach ($rows as $row) {
                $months[$row->ym] = (int) $row->total;
            }

            // Convertir en tableau de données pour le graphique
            $data = array_map(function($ym, $total) {
                return [
                    'name' => $ym,
                    'clients' => $total,
                ];
            }, array_keys($months), array_values($months));

            return response()->json($data);
        } catch (\Throwable $e) {
            return response()->json([], 200);
        }
    }

    /**
     * Retourne les années disponibles pour le filtre du graphique.
     */
    public function availableYears(Request $request)
    {
        try {
            // Essayer d'abord d'utiliser la table demande_ouverture_compte
            try {
                $years = DB::table('demande_ouverture_compte')
                    ->selectRaw('DISTINCT YEAR(date_creation) as year')
                    ->whereNotNull('date_creation')
                    ->orderBy('year', 'desc')
                    ->pluck('year')
                    ->toArray();
            } catch (\Exception $e) {
                // Si la table n'existe pas ou n'est pas accessible, utiliser la table tiers
                $years = Tier::query()
                    ->selectRaw('DISTINCT YEAR(created_at) as year')
                    ->whereNotNull('created_at')
                    ->orderBy('year', 'desc')
                    ->pluck('year')
                    ->toArray();
            }
            
            if (empty($years)) {
                $years = [Carbon::now()->year];
            }
            
            return response()->json($years);
        } catch (\Throwable $e) {
            return response()->json([Carbon::now()->year], 200);
        }
    }

    /**
     * Fournit la répartition des clients par type.
     */
    public function typeBreakdown(Request $request)
    {
        try {
            // Couleurs pour chaque type de client
            $colors = [
                'Client' => '#3b82f6',
                'Fournisseur' => '#10b981',
                'Salariés' => '#f59e0b',
                'Autre' => '#8b5cf6'
            ];

            // Essayer d'abord d'utiliser la table demande_ouverture_compte
            try {
                // Vérifier si la colonne type_tiers existe dans la table demande_ouverture_compte
                if (Schema::hasColumn('demande_ouverture_compte', 'type_tiers')) {
                    $rows = DB::table('demande_ouverture_compte')
                        ->selectRaw("type_tiers as type, COUNT(*) as total")
                        ->groupBy('type_tiers')
                        ->get();
                } else {
                    // Si la colonne n'existe pas, utiliser la table tiers
                    throw new \Exception('Colonne type_tiers non trouvée dans demande_ouverture_compte');
                }
            } catch (\Exception $e) {
                // Si la table n'existe pas ou n'est pas accessible, utiliser la table tiers
                $rows = Tier::query()
                    ->selectRaw("type_tiers as type, COUNT(*) as total")
                    ->groupBy('type_tiers')
                    ->get();
            }

            // Convertir en tableau de données pour le graphique
            $data = [];
            foreach ($rows as $row) {
                $typeName = $row->type ?? 'Inconnu';
                // Si le type est vide ou null, le regrouper sous "Inconnu"
                if (empty($typeName)) {
                    $typeName = 'Inconnu';
                }
                
                $data[] = [
                    'name' => $typeName,
                    'value' => (int) $row->total,
                    'color' => $colors[$typeName] ?? $colors['Autre']
                ];
            }

            // S'assurer que "Salariés" est toujours inclus même s'il n'y a pas de données
            $hasSalaries = false;
            foreach ($data as $item) {
                if ($item['name'] === 'Salariés') {
                    $hasSalaries = true;
                    break;
                }
            }
            
            if (!$hasSalaries) {
                $data[] = [
                    'name' => 'Salariés',
                    'value' => 0,
                    'color' => $colors['Salariés']
                ];
            }

            return response()->json($data);
        } catch (\Throwable $e) {
            \Log::error('Erreur dans typeBreakdown: ' . $e->getMessage());
            return response()->json([], 200);
        }
    }
}