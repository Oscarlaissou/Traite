<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;

class ClientApprovalHistoryController extends Controller
{
    /**
     * Récupérer l'historique des clients approuvés/rejetés pour un utilisateur spécifique
     */
    public function index(Request $request)
    {
        try {
            // 1. Sécurité : Vérifier l'authentification
            if (!Auth::check()) {
                return response()->json(['error' => 'Utilisateur non authentifié'], 401);
            }

            // On utilise l'ID de l'utilisateur connecté par défaut
            $authUserId = Auth::id();
            
            // Si un paramètre created_by est passé et que l'utilisateur veut voir un autre (optionnel)
            // Ici, on force l'utilisateur à voir SEULEMENT ses propres données pour l'instant
            $targetUserId = $authUserId;

            Log::info('ClientApprovalHistoryController: Fetching history', [
                'target_user_id' => $targetUserId
            ]);
            
            // 2. Requête SQL améliorée pour récupérer l'historique des clients
            $history = DB::table('client_approvals as ca')
                ->select(
                    'ca.id',
                    'ca.tier_id as client_id',
                    'ca.status',
                    'ca.rejection_reason',
                    'ca.created_at',
                    'ca.approved_tier_id',
                    DB::raw('CASE 
                        WHEN ca.status = "approved" AND ca.approved_tier_id IS NOT NULL THEN (
                            SELECT t.nom_raison_sociale 
                            FROM tiers t 
                            WHERE t.id = ca.approved_tier_id
                        )
                        WHEN ca.status = "rejected" THEN (
                            SELECT pc.nom_raison_sociale 
                            FROM pending_clients pc 
                            WHERE pc.id = ca.tier_id
                        )
                        WHEN ca.status = "pending" THEN (
                            SELECT pc.nom_raison_sociale 
                            FROM pending_clients pc 
                            WHERE pc.id = ca.tier_id
                        )
                        ELSE "Client inconnu"
                    END as client_name'),
                    DB::raw('CASE 
                        WHEN ca.status = "approved" AND ca.approved_tier_id IS NOT NULL THEN (
                            SELECT t.numero_compte 
                            FROM tiers t 
                            WHERE t.id = ca.approved_tier_id
                        )
                        WHEN ca.status = "rejected" THEN (
                            SELECT pc.numero_compte 
                            FROM pending_clients pc 
                            WHERE pc.id = ca.tier_id
                        )
                        WHEN ca.status = "pending" THEN (
                            SELECT pc.numero_compte 
                            FROM pending_clients pc 
                            WHERE pc.id = ca.tier_id
                        )
                        ELSE "N/A"
                    END as account_number')
                )
                ->where('ca.user_id', $targetUserId)
                ->orderBy('ca.created_at', 'desc')
                ->get();
            
            // 3. Transformation des données
            $transformedHistory = collect($history)->map(function ($record) {
                return [
                    'id' => (int) $record->id,
                    'client_id' => (int) $record->client_id,
                    'status' => $record->status,
                    'rejection_reason' => $record->rejection_reason,
                    'created_at' => $record->created_at,
                    'client_name' => $record->client_name ?? 'Client inconnu (Supprimé)',
                    'account_number' => $record->account_number ?? 'N/A'
                ];
            })->toArray();
            
            return response()->json(array_values($transformedHistory));

        } catch (\Exception $e) {
            Log::error('ClientApprovalHistoryController Error', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return response()->json(['error' => 'Erreur serveur: ' . $e->getMessage()], 500);
        }
    }
}