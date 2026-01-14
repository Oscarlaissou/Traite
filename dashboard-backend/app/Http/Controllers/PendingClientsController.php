<?php

namespace App\Http\Controllers;

use App\Models\PendingClient;
use App\Models\Tier;
use App\Models\Agence; // Added Agence model
use App\Models\User; // Added User model import
use App\Notifications\ClientApprovedNotification;
use App\Notifications\ClientRejectedNotification; // Added ClientRejectedNotification import
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;

class PendingClientsController extends Controller
{
    /**
     * Liste des catégories supportées côté métier.
     */
    public const CATEGORIES = [
        'Sté Privées Hors Grp',
        'Société Groupe',
        'Individuel',
        'Personnel Groupe',
        'Administration',
        'Collectivité locale',
        'Entreprise Publique',
        'Société de financement', // Ajout de cette catégorie
    ];

    /**
     * Store a newly created pending client in storage.
     */
    public function store(Request $request)
    {
        $validated = $request->validate([
            // Champs Tiers
            'numero_compte' => [
                'nullable',
                'string',
                'max:100',
                // Vérifier que le numéro de compte n'existe pas déjà dans les tiers existants
                Rule::unique('tiers', 'numero_compte'),
                // Vérifier que le numéro de compte n'existe pas déjà dans les clients en attente
                Rule::unique('pending_clients', 'numero_compte')
            ],
            'nom_raison_sociale' => ['required', 'string', 'max:255'],
            'bp' => ['nullable', 'string', 'max:255'],
            'ville' => ['nullable', 'string', 'max:255'],
            'pays' => ['nullable', 'string', 'max:255'],
            'adresse_geo_1' => ['nullable', 'string', 'max:255'],
            'adresse_geo_2' => ['nullable', 'string', 'max:255'],
            'telephone' => ['nullable', 'string', 'max:50', 'regex:/^[0-9]+$/'],
            'email' => ['nullable', 'email', 'max:255'],
            'categorie' => ['required', 'string', Rule::in(self::CATEGORIES)],
            'n_contribuable' => ['nullable', 'string', 'max:100'],
            'type_tiers' => ['required', 'string', Rule::in(['Client', 'Fournisseur', 'Salariés'])],

            // Champs Demande d'ouverture de compte
            'date_creation' => ['nullable', 'date'],
            'montant_facture' => ['nullable', 'numeric', 'min:0'],
            'montant_paye' => ['nullable', 'numeric', 'min:0'],
            'credit' => ['nullable', 'numeric'],
            'motif' => ['nullable', 'string', 'max:1000'],
            'etablissement' => ['nullable', 'string', 'max:255'],
            'service' => ['nullable', 'string', 'max:255'],
            'nom_signataire' => ['nullable', 'string', 'max:255'],
        ]);

        try {
            // Ajouter l'ID de l'utilisateur qui crée le client
            $validated['created_by'] = Auth::id();

            // Créer le client en attente
            $pendingClient = PendingClient::create($validated);

            return response()->json($pendingClient, 201, [], JSON_UNESCAPED_UNICODE);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => 'Une erreur est survenue lors de l\'enregistrement.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Display a listing of the pending clients.
     */
    public function index()
    {
        // Récupérer uniquement les clients en attente qui n'ont pas été rejetés et qui ne sont pas approuvés
        $pendingClients = PendingClient::with('createdBy:id,username')
            ->where('pending_clients.status', 'pending') // Seulement les clients en attente
            ->whereNotExists(function ($query) {
                $query->select(DB::raw(1))
                    ->from('client_approvals')
                    ->whereColumn('client_approvals.tier_id', 'pending_clients.id')
                    ->where('client_approvals.status', 'rejected');
            })
            ->whereNotExists(function ($query) {
                $query->select(DB::raw(1))
                    ->from('client_approvals')
                    ->whereColumn('client_approvals.tier_id', 'pending_clients.id')
                    ->where('client_approvals.status', 'approved');
            })
            ->get();
        
        // Log pour debugger les données
        \Log::info('Pending clients data:', ['count' => $pendingClients->count(), 'clients' => $pendingClients->toArray()]);
        
        return response()->json([
            'data' => $pendingClients,
            'count' => $pendingClients->count(),
        ], 200, [], JSON_UNESCAPED_UNICODE);
    }

    /**
     * Display the specified pending client.
     */
    public function show(PendingClient $pendingClient)
    {
        // Vérifier si le client existe encore dans pending_clients
        if (!$pendingClient || !$pendingClient->exists) {
            \Log::info('Pending client not found in pending_clients table', [
                'pending_client_id' => request()->route('pendingClient')
            ]);
            
            // Vérifier s'il existe dans la table tiers (cas où le client a été approuvé)
            $approvedClient = \App\Models\Tier::find(request()->route('pendingClient'));
            if ($approvedClient) {
                \Log::info('Client found in tiers table (already approved)', [
                    'tier_id' => $approvedClient->id
                ]);
                
                return response()->json([
                    'message' => 'Client déjà approuvé.',
                    'client' => $approvedClient,
                    'status' => 'approved'
                ], 200, [], JSON_UNESCAPED_UNICODE);
            }
            
            return response()->json([
                'message' => 'Client en attente non trouvé. Il a peut-être déjà été approuvé ou supprimé.'
            ], 404);
        }
        
        $pendingClient->load('createdBy:id,username');
        
        // Log pour debugger les données
        \Log::info('Showing pending client:', ['client' => $pendingClient->toArray()]);
        
        return response()->json($pendingClient, 200, [], JSON_UNESCAPED_UNICODE);
    }

    /**
     * Approve a pending client and move it to the tiers table.
     */
    public function approve(PendingClient $pendingClient)
    {
        try {
            // Vérifier si un client avec le même numéro de compte existe déjà
            if ($pendingClient->numero_compte && Tier::where('numero_compte', $pendingClient->numero_compte)->exists()) {
                return response()->json([
                    'message' => 'Un client avec ce numéro de compte existe déjà.',
                ], 400);
            }

            // Utilisation d'une transaction pour garantir que les deux opérations réussissent ou échouent ensemble.
            $tier = DB::transaction(function () use ($pendingClient) {
                // 1. Préparer les données pour la création du Tiers.
                $tierData = [
                    'numero_compte' => $pendingClient->numero_compte,
                    'nom_raison_sociale' => $pendingClient->nom_raison_sociale,
                    'bp' => $pendingClient->bp,
                    'ville' => $pendingClient->ville,
                    'pays' => $pendingClient->pays,
                    'adresse_geo_1' => $pendingClient->adresse_geo_1,
                    'adresse_geo_2' => $pendingClient->adresse_geo_2,
                    'telephone' => $pendingClient->telephone,
                    'email' => $pendingClient->email,
                    'categorie' => $pendingClient->categorie,
                    'n_contribuable' => $pendingClient->n_contribuable,
                    'type_tiers' => $pendingClient->type_tiers,
                ];

                // Crée le nouveau Tiers en base de données.
                $newTier = Tier::create($tierData);

                // Si la table demande_ouverture_compte existe, créer également l'entrée
                if (DB::getSchemaBuilder()->hasTable('demande_ouverture_compte')) {
                    $demandeColumns = DB::getSchemaBuilder()->getColumnListing('demande_ouverture_compte');
                    
                    if (!empty($demandeColumns)) {
                        // Find or create the agency
                        $agenceId = null;
                        if (!empty($pendingClient->etablissement)) {
                            $agence = Agence::firstOrCreate(
                                [
                                    'etablissement' => $pendingClient->etablissement,
                                    'service' => $pendingClient->service,
                                    'nom_signataire' => $pendingClient->nom_signataire
                                ],
                                [
                                    'etablissement' => $pendingClient->etablissement,
                                    'service' => $pendingClient->service,
                                    'nom_signataire' => $pendingClient->nom_signataire
                                ]
                            );
                            $agenceId = $agence->id;
                        }

                        $demandeData = [
                            'id' => $newTier->id,
                            'date_creation' => $pendingClient->date_creation,
                            'montant_facture' => $pendingClient->montant_facture,
                            'montant_paye' => $pendingClient->montant_paye,
                            'credit' => $pendingClient->credit,
                            'motif' => $pendingClient->motif,
                            'agence_id' => $agenceId, // Use agence_id instead of direct fields
                            'created_at' => now(),
                            'updated_at' => now(),
                        ];

                        // Filtrer les colonnes qui existent dans la table
                        $filteredData = array_intersect_key($demandeData, array_flip($demandeColumns));
                        
                        if (!empty($filteredData)) {
                            DB::table('demande_ouverture_compte')->insert($filteredData);
                        }
                    }
                }

                // Enregistrer l'activité de création avec les informations de l'utilisateur d'origine
                try {
                    $originalCreator = $pendingClient->createdBy;
                    $originalUsername = $originalCreator ? ($originalCreator->username ?? $originalCreator->name ?? $originalCreator->email ?? 'Utilisateur') : null;
                    $approvingUser = \Illuminate\Support\Facades\Auth::user();
                    
                    $changes = null;
                    if ($originalUsername) {
                        $changes = [
                            'original_creator' => [
                                'username' => $originalUsername
                            ]
                        ];
                    }
                    
                    \App\Models\TierActivity::create([
                        'tier_id' => $newTier->id,
                        'user_id' => optional($approvingUser)->id,
                        'action' => 'Création',
                        'changes' => $changes,
                    ]);
                } catch (\Throwable $e) {
                    // ignore logging failures
                }

                // Envoyer une notification à l'utilisateur qui a créé le client en attente
                // Ne pas envoyer de notification à l'utilisateur qui approuve le client
                if ($pendingClient->created_by && $pendingClient->created_by != Auth::id()) {
                    $creator = User::find($pendingClient->created_by);
                    if ($creator) {
                        $creator->notify(new ClientApprovedNotification(
                            $pendingClient->nom_raison_sociale,
                            $pendingClient->numero_compte,
                            $pendingClient->id
                        ));
                    }
                }

                // Enregistrer l'approbation dans la table client_approvals
                try {
                    // Utiliser l'ID original du pending_client comme tier_id
                    // pour maintenir la cohérence avec les enregistrements rejetés
                    $originalClientId = $pendingClient->id;
                    
                    // Vérifier s'il existe déjà un enregistrement pour ce client
                    $existingRecord = \Illuminate\Support\Facades\DB::table('client_approvals')
                        ->where('tier_id', $originalClientId)
                        ->first();
                    
                    if ($existingRecord) {
                        // Mettre à jour l'enregistrement existant
                        \Illuminate\Support\Facades\DB::table('client_approvals')
                            ->where('id', $existingRecord->id)
                            ->update([
                                'status' => 'approved',
                                'rejection_reason' => null,
                                'updated_at' => now(),
                                // Stocker l'ID du client approuvé dans la table tiers
                                'approved_tier_id' => $newTier->id,
                            ]);
                    } else {
                        // Créer un nouvel enregistrement
                        \Illuminate\Support\Facades\DB::table('client_approvals')->insert([
                            'tier_id' => $originalClientId,
                            'user_id' => $pendingClient->created_by,
                            'status' => 'approved',
                            'created_at' => now(),
                            'updated_at' => now(),
                            // Stocker l'ID du client approuvé dans la table tiers
                            'approved_tier_id' => $newTier->id,
                        ]);
                    }
                } catch (\Throwable $e) {
                    // Log error but don't stop the process
                    \Log::error('Error inserting/updating client approval record: ' . $e->getMessage());
                }

                // Mettre à jour le statut du client en attente au lieu de le supprimer
                $pendingClient->update(['status' => 'approved']);

                return $newTier;
            });

            // Broadcast event to update pending clients count
            broadcast(new \App\Events\PendingClientsCountUpdated());

            // Si la transaction a réussi, renvoyer le Tiers avec un statut 201 Created.
            return response()->json($tier, 201, [], JSON_UNESCAPED_UNICODE);
        } catch (\Throwable $e) {
            // Si une erreur survient (validation, contrainte BDD, etc.), la transaction est annulée.
            // On renvoie un message d'erreur clair au front-end.
            \Log::error('Error approving pending client: ' . $e->getMessage(), [
                'exception' => $e,
                'pending_client_id' => $pendingClient->id,
                'pending_client_data' => $pendingClient->toArray()
            ]);
            
            return response()->json([
                'message' => 'Une erreur est survenue lors de l\'approbation du client.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Reject a pending client and notify the creator.
     */
    public function reject(PendingClient $pendingClient, Request $request)
    {
        // Validate that the pending client exists
        if (!$pendingClient || !$pendingClient->exists) {
            \Log::error('Pending client not found', [
                'pending_client_id' => $request->route('pendingClient')
            ]);
            
            return response()->json([
                'message' => 'Client en attente non trouvé.'
            ], 404);
        }
        
        // Validate user authentication
        $user = Auth::user();
        if (!$user) {
            \Log::error('User not authenticated when trying to reject pending client', [
                'pending_client_id' => $pendingClient->id
            ]);
            
            return response()->json([
                'message' => 'Utilisateur non authentifié.'
            ], 401);
        }
        
        // Validate user permissions
        if (!$user->hasPermission('manage_pending_clients')) {
            \Log::error('User does not have permission to reject pending clients', [
                'user_id' => $user->id,
                'pending_client_id' => $pendingClient->id
            ]);
            
            return response()->json([
                'message' => 'Permission refusée.'
            ], 403);
        }
        
        try {
            \Log::info('Starting client rejection process', [
                'pending_client_id' => $pendingClient->id,
                'pending_client_name' => $pendingClient->nom_raison_sociale,
                'created_by' => $pendingClient->created_by,
                'current_user_id' => Auth::id()
            ]);
            
            $validated = $request->validate([
                'reason' => ['nullable', 'string', 'max:1000']
            ]);

            $reason = $validated['reason'] ?? null;
            $clientName = $pendingClient->nom_raison_sociale;

            // Envoyer une notification à l'utilisateur qui a créé le client en attente
            // Ne pas envoyer de notification à l'utilisateur qui rejette le client
            if ($pendingClient->created_by && $pendingClient->created_by != Auth::id()) {
                \Log::info('Sending rejection notification to creator', [
                    'creator_id' => $pendingClient->created_by
                ]);
                try {
                    $creator = User::find($pendingClient->created_by);
                    if ($creator) {
                        $creator->notify(new ClientRejectedNotification($clientName, $reason, $pendingClient->id));
                        \Log::info('Rejection notification sent successfully');
                    } else {
                        \Log::warning('Creator not found for notification', [
                            'creator_id' => $pendingClient->created_by
                        ]);
                    }
                } catch (\Exception $notificationError) {
                    \Log::error('Error sending rejection notification: ' . $notificationError->getMessage(), [
                        'exception' => $notificationError,
                        'pending_client_id' => $pendingClient->id,
                        'creator_id' => $pendingClient->created_by
                    ]);
                    // Continue with the process even if notification fails
                }
            } else {
                \Log::info('Skipping notification - same user or no creator', [
                    'created_by' => $pendingClient->created_by,
                    'current_user_id' => Auth::id()
                ]);
            }

            // Enregistrer le rejet dans la table client_approvals
            try {
                // Vérifier s'il existe déjà un enregistrement pour ce client
                $existingRecord = \Illuminate\Support\Facades\DB::table('client_approvals')
                    ->where('tier_id', $pendingClient->id)
                    ->first();
                
                if ($existingRecord) {
                    // Mettre à jour l'enregistrement existant
                    // Toujours mettre le statut à "rejected" lors d'un rejet
                    \Illuminate\Support\Facades\DB::table('client_approvals')
                        ->where('id', $existingRecord->id)
                        ->update([
                            'status' => 'rejected',
                            'rejection_reason' => $reason,
                            'updated_at' => now(),
                        ]);
                } else {
                    // Créer un nouvel enregistrement
                    \Illuminate\Support\Facades\DB::table('client_approvals')->insert([
                        'tier_id' => $pendingClient->id, // Using the pending client ID since it wasn't moved to tiers
                        'user_id' => $pendingClient->created_by,
                        'status' => 'rejected',
                        'rejection_reason' => $reason,
                        'created_at' => now(),
                        'updated_at' => now(),
                    ]);
                }
            } catch (\Throwable $e) {
                // Log error but don't stop the process
                \Log::error('Error inserting/updating client rejection record: ' . $e->getMessage());
            }

            // Mettre à jour le statut du client en attente au lieu de le supprimer
            $pendingClient->update(['status' => 'rejected']);

            // Broadcast event to update pending clients count
            \Log::info('Broadcasting pending clients count update');
            try {
                broadcast(new \App\Events\PendingClientsCountUpdated());
                \Log::info('Pending clients count update broadcasted successfully');
            } catch (\Exception $broadcastError) {
                \Log::error('Error broadcasting pending clients count update: ' . $broadcastError->getMessage(), [
                    'exception' => $broadcastError
                ]);
                // Continue with the process even if broadcast fails
            }

            \Log::info('Client rejection completed successfully', [
                'pending_client_id' => $pendingClient->id
            ]);
            
            return response()->json([
                'message' => 'Client en attente rejeté avec succès.'
            ], 200, [], JSON_UNESCAPED_UNICODE);
        } catch (\Throwable $e) {
            \Log::error('Error rejecting pending client: ' . $e->getMessage(), [
                'exception' => $e,
                'pending_client_id' => $pendingClient->id ?? null,
                'trace' => $e->getTraceAsString()
            ]);
            
            return response()->json([
                'message' => 'Une erreur est survenue lors du rejet du client en attente.',
                'error' => $e->getMessage(),
                'details' => config('app.debug') ? [
                    'file' => $e->getFile(),
                    'line' => $e->getLine(),
                    'trace' => $e->getTraceAsString()
                ] : null
            ], 500);
        }
    }

    /**
     * Remove the specified pending client from storage.
     */
    public function destroy(PendingClient $pendingClient)
    {
        try {
            $pendingClient->delete();
            
            return response()->json([
                'message' => 'Client en attente supprimé avec succès.'
            ], 200, [], JSON_UNESCAPED_UNICODE);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => 'Une erreur est survenue lors de la suppression du client en attente.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Update the specified pending client in storage.
     */
    public function update(Request $request, PendingClient $pendingClient)
    {
        // Validate that the pending client exists
        if (!$pendingClient || !$pendingClient->exists) {
            \Log::error('Pending client not found for update', [
                'pending_client_id' => $request->route('pendingClient')
            ]);
            
            return response()->json([
                'message' => 'Client en attente non trouvé.'
            ], 404);
        }
        
        try {
            $validated = $request->validate([
                // Champs Tiers
                'numero_compte' => [
                    'nullable',
                    'string',
                    'max:100',
                    // Vérifier que le numéro de compte n'existe pas déjà dans les tiers existants (sauf pour ce client s'il a été approuvé)
                    function ($attribute, $value, $fail) use ($pendingClient) {
                        if ($value) {
                            // Vérifier dans la table tiers
                            $query = \App\Models\Tier::where('numero_compte', $value);
                            
                            // Si le client a été approuvé, ignorer le tier correspondant
                            $approvalRecord = \Illuminate\Support\Facades\DB::table('client_approvals')
                                ->where('tier_id', $pendingClient->id)
                                ->where('status', 'approved')
                                ->first();
                            
                            if ($approvalRecord && $approvalRecord->approved_tier_id) {
                                $query->where('id', '!=', $approvalRecord->approved_tier_id);
                            }
                            
                            if ($query->exists()) {
                                $fail('Le numéro de compte est déjà utilisé.');
                            }
                        }
                    },
                    // Vérifier que le numéro de compte n'existe pas déjà dans les clients en attente (sauf pour ce client)
                    Rule::unique('pending_clients', 'numero_compte')->ignore($pendingClient->id)
                ],
                'nom_raison_sociale' => ['required', 'string', 'max:255'],
                'bp' => ['nullable', 'string', 'max:255'],
                'ville' => ['nullable', 'string', 'max:255'],
                'pays' => ['nullable', 'string', 'max:255'],
                'adresse_geo_1' => ['nullable', 'string', 'max:255'],
                'adresse_geo_2' => ['nullable', 'string', 'max:255'],
                'telephone' => ['nullable', 'string', 'max:50', 'regex:/^[0-9]+$/'],
                'email' => ['nullable', 'email', 'max:255'],
                'categorie' => ['required', 'string', Rule::in(self::CATEGORIES)],
                'n_contribuable' => ['nullable', 'string', 'max:100'],
                'type_tiers' => ['required', 'string', Rule::in(['Client', 'Fournisseur', 'Salariés'])],

                // Champs Demande d'ouverture de compte
                'date_creation' => ['nullable', 'date'],
                'montant_facture' => ['nullable', 'numeric', 'min:0'],
                'montant_paye' => ['nullable', 'numeric', 'min:0'],
                'credit' => ['nullable', 'numeric'],
                'motif' => ['nullable', 'string', 'max:1000'],
                'etablissement' => ['nullable', 'string', 'max:255'],
                'service' => ['nullable', 'string', 'max:255'],
                'nom_signataire' => ['nullable', 'string', 'max:255'],
            ]);

            // Mettre à jour le client en attente
            $pendingClient->update($validated);

            // Recharger le client avec les relations
            $pendingClient->load('createdBy:id,username');
            
            \Log::info('Pending client updated successfully', [
                'pending_client_id' => $pendingClient->id,
                'updated_data' => $validated
            ]);
            
            return response()->json($pendingClient, 200, [], JSON_UNESCAPED_UNICODE);
        } catch (\Illuminate\Validation\ValidationException $e) {
            \Log::error('Validation error updating pending client', [
                'pending_client_id' => $pendingClient->id,
                'errors' => $e->errors(),
                'input' => $request->all()
            ]);
            
            return response()->json([
                'message' => 'Données invalides.',
                'errors' => $e->errors()
            ], 422);
        } catch (\Throwable $e) {
            \Log::error('Error updating pending client: ' . $e->getMessage(), [
                'exception' => $e,
                'pending_client_id' => $pendingClient->id,
                'input' => $request->all()
            ]);
            
            return response()->json([
                'message' => 'Une erreur est survenue lors de la mise à jour du client en attente.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Submit a pending client for approval (resubmit after rejection).
     */
    public function submit(PendingClient $pendingClient)
    {
        // Validate that the pending client exists
        if (!$pendingClient || !$pendingClient->exists) {
            \Log::error('Pending client not found for submission', [
                'pending_client_id' => request()->route('pendingClient')
            ]);
            
            return response()->json([
                'message' => 'Client en attente non trouvé.'
            ], 404);
        }
        
        try {
            \Log::info('Starting client resubmission process', [
                'pending_client_id' => $pendingClient->id,
                'pending_client_name' => $pendingClient->nom_raison_sociale,
                'created_by' => $pendingClient->created_by,
                'current_user_id' => Auth::id()
            ]);
            
            // Vérifier s'il existe un enregistrement dans client_approvals
            $existingRecord = \Illuminate\Support\Facades\DB::table('client_approvals')
                ->where('tier_id', $pendingClient->id)
                ->first();
            
            if (!$existingRecord) {
                \Log::warning('No record found for resubmission, creating new one', [
                    'pending_client_id' => $pendingClient->id
                ]);
                
                // Créer un nouvel enregistrement s'il n'existe pas
                try {
                    \Illuminate\Support\Facades\DB::table('client_approvals')->insert([
                        'tier_id' => $pendingClient->id,
                        'user_id' => $pendingClient->created_by,
                        'status' => 'pending',
                        'created_at' => now(),
                        'updated_at' => now(),
                    ]);
                } catch (\Throwable $e) {
                    \Log::error('Error creating client approval record: ' . $e->getMessage());
                }
            } else {
                // Mettre à jour le statut dans la table client_approvals
                // La soumission remet toujours le client dans l'état "pending"
                try {
                    \Illuminate\Support\Facades\DB::table('client_approvals')
                        ->where('id', $existingRecord->id)
                        ->update([
                            'status' => 'pending',
                            'updated_at' => now(),
                        ]);
                } catch (\Throwable $e) {
                    // Log error but don't stop the process
                    \Log::error('Error updating client approval record: ' . $e->getMessage());
                }
            }
            
            // Mettre à jour le statut du client en attente - utiliser update directement sans passer par le modèle
            try {
                $pendingClient->status = 'pending';
                $pendingClient->save();
            } catch (\Throwable $e) {
                \Log::error('Error updating pending client status: ' . $e->getMessage(), [
                    'exception' => $e,
                    'pending_client_id' => $pendingClient->id,
                    'trace' => $e->getTraceAsString()
                ]);
                throw $e; // Relancer l'exception pour qu'elle soit gérée par le bloc catch externe
            }
            
            \Log::info('Client resubmission completed successfully', [
                'pending_client_id' => $pendingClient->id
            ]);
            
            return response()->json([
                'message' => 'Client soumis pour approbation avec succès.'
            ], 200, [], JSON_UNESCAPED_UNICODE);
        } catch (\Throwable $e) {
            \Log::error('Error resubmitting pending client: ' . $e->getMessage(), [
                'exception' => $e,
                'pending_client_id' => $pendingClient->id ?? null,
                'trace' => $e->getTraceAsString()
            ]);
            
            return response()->json([
                'message' => 'Une erreur est survenue lors de la mise à jour du client en attente.',
                'error' => $e->getMessage(),
                'details' => config('app.debug') ? [
                    'file' => $e->getFile(),
                    'line' => $e->getLine(),
                    'trace' => $e->getTraceAsString()
                ] : null
            ], 500);
        }
    }
}