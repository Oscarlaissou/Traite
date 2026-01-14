<?php

namespace App\Http\Controllers;

use App\Models\Tier;
use App\Models\Agence; // Added Agence model
use App\Models\TierActivity;
use App\Models\OrganizationSetting;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Validator;

/**
 * Contrôleur REST permettant d'exposer la grille des clients (tiers).
 */
class TiersController extends Controller
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
        'Administration Privée',
        'Société de financement', // Ajout de cette catégorie
    ];

    /**
     * Tableau de correspondance entre les alias métier et les colonnes physiques éventuelles.
     *
     * @var array<string, array<int, string>>
     */
    private array $columnCandidates = [
        'numero_compte' => ['numero_compte', 'num_compte', 'compte', 'account_number'],
        'nom_raison_sociale' => ['nom_raison_sociale', 'raison_sociale', 'nom', 'nom_tiers', 'nom_client'],
        'bp' => ['bp', 'boite_postale', 'boite_postale_1', 'boite_postale_client'],
        'ville' => ['ville', 'city', 'localite'],
        'pays' => ['pays', 'country', 'nation'],
        'categorie' => ['categorie', 'category', 'type_client', 'type'],
        'type_tiers' => ['type_tiers', 'type_party', 'party_type'],
    ];

    /**
     * Colonnes effectivement présentes dans la table (déterminé dynamiquement).
     *
     * @var array<string, string>
     */
    private array $resolvedColumns = [];

    /**
     * Colonnes disponibles sur la table demande_ouverture_compte (si présente).
     *
     * @var array<int, string>
     */
    private array $demandeColumns = [];

    public function __construct()
    {
        $this->resolvedColumns = $this->resolveColumns();
        $this->demandeColumns = Schema::hasTable('demande_ouverture_compte')
            ? Schema::getColumnListing('demande_ouverture_compte')
            : [];
    }

    /**
     * Retourne la liste paginée des clients avec recherche, tri et filtrage.
     */
    public function index(Request $request): JsonResponse
    {
        $query = Tier::query();

        // Sélectionner les colonnes pertinentes uniquement pour optimiser la charge.
        $selectColumns = array_unique(array_merge(['id'], array_values($this->resolvedColumns)));
        $query->select($selectColumns);

        // Recherche full-text simple sur les colonnes principales.
        if ($search = trim((string) $request->get('search', ''))) {
            $query->where(function ($q) use ($search) {
                foreach ($this->resolvedColumns as $column) {
                    $q->orWhere($column, 'like', "%{$search}%");
                }
            });
        }

        // Filtrage par catégorie (supporte une ou plusieurs valeurs).
        $categoryFilter = $request->input('categorie');
        $categories = $this->normaliseCategoryFilter($categoryFilter);
        if (!empty($categories) && $resolvedCategoryColumn = ($this->resolvedColumns['categorie'] ?? null)) {
            $query->whereIn($resolvedCategoryColumn, $categories);
        }

        // Filtrage par type_tiers
        $typeTiersFilter = $request->input('type_tiers');
        if (!empty($typeTiersFilter) && $resolvedTypeTiersColumn = ($this->resolvedColumns['type_tiers'] ?? null)) {
            $query->where($resolvedTypeTiersColumn, $typeTiersFilter);
        }

        // Tri configurable sur un sous-ensemble de colonnes.
        $sortRequest = (string) $request->get('sort', 'nom_raison_sociale');
        $direction = strtolower((string) $request->get('dir', 'asc')) === 'desc' ? 'desc' : 'asc';

        $allowedSorts = [
            'numero_compte' => $this->resolvedColumns['numero_compte'] ?? 'numero_compte',
            'nom_raison_sociale' => $this->resolvedColumns['nom_raison_sociale'] ?? 'nom_raison_sociale',
            'bp' => $this->resolvedColumns['bp'] ?? 'bp',
            'ville' => $this->resolvedColumns['ville'] ?? 'ville',
            'pays' => $this->resolvedColumns['pays'] ?? 'pays',
            'categorie' => $this->resolvedColumns['categorie'] ?? 'categorie',
        ];

        if (!array_key_exists($sortRequest, $allowedSorts)) {
            $sortRequest = 'nom_raison_sociale';
        }

        $query->orderBy($allowedSorts[$sortRequest], $direction);

        // Pagination paramétrable (borne haute pour éviter les abus).
        $perPage = max(1, min((int) $request->get('per_page', 10), 200));
        $results = $query->paginate($perPage);

        // Projection des colonnes physiques vers les alias attendus côté frontend.
        $collection = $results->getCollection()->map(function (Tier $tier) {
            return [
                'id' => $tier->getKey(),
                'numero_compte' => $this->extractValue($tier, 'numero_compte'),
                'nom_raison_sociale' => $this->extractValue($tier, 'nom_raison_sociale'),
                'bp' => $this->extractValue($tier, 'bp'),
                'ville' => $this->extractValue($tier, 'ville'),
                'pays' => $this->extractValue($tier, 'pays'),
                'categorie' => $this->extractValue($tier, 'categorie'),
                'type_tiers' => $this->extractValue($tier, 'type_tiers'),
            ];
        });

        $results->setCollection($collection);

        return response()->json([
            'data' => $results->items(),
            'current_page' => $results->currentPage(),
            'last_page' => $results->lastPage(),
            'per_page' => $results->perPage(),
            'total' => $results->total(),
            'available_categories' => self::CATEGORIES,
        ], 200, [], JSON_UNESCAPED_UNICODE);
    }

    /**
     * Création d'un client (tier) et de sa demande d'ouverture de compte associée de manière transactionnelle.
     */
    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            // Champs Tiers
            'numero_compte' => [
                'nullable',
                'string',
                'max:4', // Changé de 100 à 4 pour correspondre au nouveau format
                'regex:/^\d{4}$/', // Ajout d'une règle regex pour s'assurer que c'est un nombre à 4 chiffres
                Rule::unique('tiers', 'numero_compte')
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
            // Utilisation d'une transaction pour garantir que les deux insertions réussissent ou échouent ensemble.
            $tier = DB::transaction(function () use ($validated) {
                // 1. Préparer les données pour la création du Tiers.
                $tierData = [
                    'numero_compte' => $validated['numero_compte'] ?? $this->generateNextAccountNumber(),
                    'nom_raison_sociale' => $validated['nom_raison_sociale'],
                    'bp' => $validated['bp'] ?? '',
                    'ville' => $validated['ville'] ?? '',
                    'pays' => $validated['pays'] ?? 'Cameroun', // Valeur par défaut
                    'adresse_geo_1' => $validated['adresse_geo_1'] ?? '', // Valeur par défaut vide au lieu de null
                    'adresse_geo_2' => $validated['adresse_geo_2'] ?? '',
                    'telephone' => $validated['telephone'] ?? '',
                    'email' => $validated['email'] ?? '',
                    'categorie' => $validated['categorie'],
                    'n_contribuable' => $validated['n_contribuable'] ?? '',
                    'type_tiers' => $validated['type_tiers'],
                ];
                
                // Crée le nouveau Tiers en base de données.
                $newTier = Tier::create($tierData);

                if (!empty($this->demandeColumns)) {
                    $demandeData = $this->buildDemandePayload($newTier->id, $validated, null, true);
                    if ($this->shouldPersistDemande($demandeData)) {
                        DB::table('demande_ouverture_compte')->insert($demandeData);
                    }
                }

                // Enregistrer l'activité de création
                try {
                    TierActivity::create([
                        'tier_id' => $newTier->id,
                        'user_id' => optional(Auth::user())->id,
                        'action' => 'Création',
                        'changes' => null,
                    ]);
                } catch (\Throwable $e) {
                    // ignore logging failures
                }

                return $newTier; // La transaction retourne le Tiers créé.
            });

            // Si la transaction a réussi, renvoyer le Tiers avec un statut 201 Created.
            return response()->json($tier, 201, [], JSON_UNESCAPED_UNICODE);

        } catch (\Throwable $e) {
            // Si une erreur survient (validation, contrainte BDD, etc.), la transaction est annulée.
            // On renvoie un message d'erreur clair au front-end.
            return response()->json([
                'message' => 'Une erreur est survenue lors de l\'enregistrement.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Résout dynamiquement la correspondance entre les alias et les colonnes disponibles.
     *
     * @return array<string, string>
     */
    private function resolveColumns(): array
    {
        $resolved = [];
        foreach ($this->columnCandidates as $alias => $candidates) {
            $found = Arr::first($candidates, fn (string $candidate) => Schema::hasColumn('tiers', $candidate));
            if ($found === null) {
                $found = $candidates[0]; //Fallback sur le premier candidat
            }
            $resolved[$alias] = $found;
        }
        return $resolved;
    }

    /**
     * Convertit la valeur du filtre catégorie en tableau exploitable.
     *
     * @param mixed $input
     * @return array<int, string>
     */
    private function normaliseCategoryFilter(mixed $input): array
    {
        if (is_array($input)) {
            $values = $input;
        } elseif (is_string($input) && strlen(trim($input)) > 0) {
            $values = preg_split('/[,;]/', $input);
        } else {
            return [];
        }

        $values = array_filter(array_map(fn ($value) => trim((string) $value), $values));
        return array_values($values);
    }

    /**
     * Récupère la valeur correspondant à l'alias fourni pour l'instance donnée.
     */
    private function extractValue(Tier $tier, string $alias): ?string
    {
        $column = $this->resolvedColumns[$alias] ?? null;
        if ($column === null) {
            return null;
        }
        $value = $tier->getAttribute($column);
        return $value === null ? null : (string) $value;
    }

    /**
     * Affiche le détail d'un client (tier).
     */
    public function show(Tier $tier): JsonResponse
    {
        // Récupère les informations de la demande d'ouverture de compte si elles existent
        $demandeQuery = DB::table('demande_ouverture_compte')
            ->where('demande_ouverture_compte.id', $tier->id); // Specify table name to avoid ambiguity
        
        // Join with agence table if it exists and agence_id column exists
        if (Schema::hasTable('agence') && in_array('agence_id', $this->demandeColumns)) {
            $demandeQuery->leftJoin('agence', 'demande_ouverture_compte.agence_id', '=', 'agence.id');
        }
        
        $demande = $demandeQuery->first();

        $payload = $tier->toArray();

        if ($demande) {
            $payload['date_creation'] = $demande->date_creation ?? null;
            $payload['montant_facture'] = $demande->montant_facture ?? null;
            $payload['montant_paye'] = $demande->montant_paye ?? null;
            $payload['credit'] = $demande->credit ?? null;
            $payload['motif'] = $demande->motif ?? null;
            
            // Get agency information from joined table or direct fields
            if (Schema::hasTable('agence') && !empty($demande->agence_id)) {
                // Get agency info from joined agence table
                $payload['etablissement'] = $demande->etablissement ?? null;
                $payload['service'] = $demande->service ?? null;
                $payload['nom_signataire'] = $demande->nom_signataire ?? null;
            } else {
                // Fallback to direct fields if they exist
                if (property_exists($demande, 'etablissement')) {
                    $payload['etablissement'] = $demande->etablissement;
                }
                if (property_exists($demande, 'service')) {
                    $payload['service'] = $demande->service;
                }
                if (property_exists($demande, 'nom_signataire')) {
                    $payload['nom_signataire'] = $demande->nom_signataire;
                }
            }
        }

        return response()->json($payload, 200, [], JSON_UNESCAPED_UNICODE);
    }

    /**
     * Supprime un client (tier).
     */
    public function destroy(Tier $tier): JsonResponse
    {
        $tier->delete();
        return response()->json(['message' => 'Client supprimé'], 200, [], JSON_UNESCAPED_UNICODE);
    }

    /**
     * Met à jour un client (tier) et sa demande d'ouverture de compte associée si fournie.
     */
    public function update(Request $request, Tier $tier): JsonResponse
    {
        $validated = $request->validate([
            // Champs Tiers
            'numero_compte' => [
                'nullable',
                'string',
                'max:4', // Changé de 100 à 4 pour correspondre au nouveau format
                'regex:/^\d{4}$/', // Ajout d'une règle regex pour s'assurer que c'est un nombre à 4 chiffres
                Rule::unique('tiers', 'numero_compte')->ignore($tier->id, 'id'),
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
            DB::transaction(function () use ($validated, $tier) {
                // Capturer les valeurs avant modification (Tiers)
                $oldValues = $tier->only([
                    'numero_compte', 'nom_raison_sociale', 'bp', 'ville', 'pays',
                    'adresse_geo_1', 'adresse_geo_2', 'telephone', 'email',
                    'categorie', 'n_contribuable', 'type_tiers'
                ]);
                
                // Capturer aussi les valeurs de la demande avant modification
                $oldDemande = null;
                if (!empty($this->demandeColumns)) {
                    $oldDemande = DB::table('demande_ouverture_compte')
                        ->where('demande_ouverture_compte.id', $tier->id) // Specify table name to avoid ambiguity
                        ->first();
                }

                // Mise à jour des champs Tiers
                $tierData = [
                    'nom_raison_sociale' => $validated['nom_raison_sociale'],
                    'bp' => $validated['bp'] ?? '',
                    'ville' => $validated['ville'] ?? '',
                    'pays' => $validated['pays'] ?? 'Cameroun', // Valeur par défaut
                    'adresse_geo_1' => $validated['adresse_geo_1'] ?? '', // Valeur par défaut vide au lieu de null
                    'adresse_geo_2' => $validated['adresse_geo_2'] ?? '',
                    'telephone' => $validated['telephone'] ?? '',
                    'email' => $validated['email'] ?? '',
                    'categorie' => $validated['categorie'],
                    'n_contribuable' => $validated['n_contribuable'] ?? '',
                    'type_tiers' => $validated['type_tiers'],
                ];
                
                // Ne pas modifier le numéro de compte existant sauf s'il est explicitement fourni
                if (isset($validated['numero_compte'])) {
                    $tierData['numero_compte'] = $validated['numero_compte'];
                }
                
                $tier->update($tierData);

                // Détecter les changements sur Tiers
                $changes = [];
                foreach ($oldValues as $key => $oldValue) {
                    $newValue = $tier->{$key};
                    if ($oldValue != $newValue) {
                        $changes[$key] = ['old' => $oldValue, 'new' => $newValue];
                    }
                }

                // Mise à jour/Création de la demande d'ouverture si la table existe
                if (!empty($this->demandeColumns)) {
                    $demande = DB::table('demande_ouverture_compte')
                        ->where('demande_ouverture_compte.id', $tier->id) // Specify table name to avoid ambiguity
                        ->first();
                    $payload = $this->buildDemandePayload($tier->id, $validated, $demande, $demande === null);
                    if ($this->shouldPersistDemande($payload)) {
                        if ($demande) {
                            unset($payload['id']); // inutile pour update
                            DB::table('demande_ouverture_compte')
                                ->where('demande_ouverture_compte.id', $tier->id) // Specify table name to avoid ambiguity
                                ->update($payload);
                            
                            // Détecter les changements sur demande_ouverture_compte
                            $demandeFields = ['etablissement', 'service', 'nom_signataire', 'montant_facture', 'montant_paye', 'credit', 'motif'];
                            foreach ($demandeFields as $field) {
                                if ($this->hasDemandeColumn($field)) {
                                    $oldVal = $oldDemande->{$field} ?? null;
                                    $newVal = $payload[$field] ?? null;
                                    if ($oldVal != $newVal) {
                                        $changes[$field] = ['old' => $oldVal, 'new' => $newVal];
                                    }
                                }
                            }
                        } else {
                            DB::table('demande_ouverture_compte')->insert($payload);
                        }
                    }
                }

                // Enregistrer l'activité de modification si des changements ont été détectés
                if (!empty($changes)) {
                    TierActivity::create([
                        'tier_id' => $tier->id,
                        'user_id' => optional(Auth::user())->id,
                        'action' => 'Modification',
                        'changes' => $changes,
                    ]);
                }
            });

            return response()->json($tier->fresh(), 200, [], JSON_UNESCAPED_UNICODE);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => 'Une erreur est survenue lors de la mise à jour.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Construit le payload pour la table demande_ouverture_compte.
     */
    private function buildDemandePayload(int $tierId, array $validated, ?object $existing = null, bool $isCreation = false): array
    {
        if (empty($this->demandeColumns)) {
            return [];
        }

        $payload = [];
        if ($isCreation && $this->hasDemandeColumn('id')) {
            $payload['id'] = $tierId;
        }

        $payload = $this->assignDemandeValue($payload, 'date_creation', $validated, $existing, now());
        $payload = $this->assignDemandeValue($payload, 'montant_facture', $validated, $existing);
        $payload = $this->assignDemandeValue($payload, 'montant_paye', $validated, $existing);
        $payload = $this->assignDemandeValue($payload, 'credit', $validated, $existing);
        $payload = $this->assignDemandeValue($payload, 'motif', $validated, $existing);
        
        // Handle agency information properly
        if (Schema::hasTable('agence')) {
            // Check if we have agency fields in the request
            $hasAgencyInfo = !empty($validated['etablissement']) || !empty($validated['service']) || !empty($validated['nom_signataire']);
            
            if ($hasAgencyInfo) {
                // Find or create the agency
                $agence = Agence::firstOrCreate(
                    [
                        'etablissement' => $validated['etablissement'] ?? '',
                        'service' => $validated['service'] ?? null,
                        'nom_signataire' => $validated['nom_signataire'] ?? null
                    ],
                    [
                        'etablissement' => $validated['etablissement'] ?? '',
                        'service' => $validated['service'] ?? null,
                        'nom_signataire' => $validated['nom_signataire'] ?? null
                    ]
                );
                
                // Add agence_id to payload if the column exists
                if ($this->hasDemandeColumn('agence_id')) {
                    $payload['agence_id'] = $agence->id;
                }
            } else if ($existing && !empty($existing->agence_id)) {
                // Keep existing agence_id if no new agency info provided
                $payload['agence_id'] = $existing->agence_id;
            }
        } else {
            // Fallback to direct fields if agence table doesn't exist
            $payload = $this->assignDemandeValue($payload, 'etablissement', $validated, $existing);
            $payload = $this->assignDemandeValue($payload, 'service', $validated, $existing);
            $payload = $this->assignDemandeValue($payload, 'nom_signataire', $validated, $existing);
        }

        if ($isCreation && $this->hasDemandeColumn('created_at')) {
            $payload['created_at'] = now();
        }
        if ($this->hasDemandeColumn('updated_at')) {
            $payload['updated_at'] = now();
        }

        $this->applyDemandeUser($payload);

        return $payload;
    }

    private function assignDemandeValue(array $payload, string $column, array $validated, ?object $existing, $default = null): array
    {
        if (!$this->hasDemandeColumn($column)) {
            return $payload;
        }

        if (array_key_exists($column, $validated)) {
            $value = $validated[$column];
            // Pour les dates, s'assurer qu'elles sont au bon format
            if ($column === 'date_creation' && $value !== null && $value !== '') {
                $parsedDate = $this->parseDateValue($value);
                $payload[$column] = $parsedDate ?: $value;
            } else {
                $payload[$column] = $value;
            }
        } elseif ($existing && property_exists($existing, $column)) {
            $payload[$column] = $existing->{$column};
        } elseif ($default !== null) {
            $payload[$column] = $default;
        } else {
            $payload[$column] = null;
        }

        return $payload;
    }

    private function hasDemandeColumn(string $column): bool
    {
        return in_array($column, $this->demandeColumns, true);
    }

    private function applyDemandeUser(array &$payload): void
    {
        $user = Auth::user();
        if (!$user) {
            return;
        }

        $username = $user->username ?? $user->name ?? $user->email ?? 'Utilisateur';

        if ($this->hasDemandeColumn('user_id')) {
            $payload['user_id'] = $user->id;
        } elseif ($this->hasDemandeColumn('utilisateur_id')) {
            $payload['utilisateur_id'] = $user->id;
        } elseif ($this->hasDemandeColumn('utilisateur')) {
            $payload['utilisateur'] = $username;
        }
    }

    private function shouldPersistDemande(array $payload): bool
    {
        foreach ($payload as $key => $value) {
            if (in_array($key, ['id', 'created_at', 'updated_at', 'user_id', 'utilisateur_id', 'utilisateur'], true)) {
                continue;
            }
            if ($value !== null && $value !== '') {
                return true;
            }
        }
        return false;
    }

    /**
     * Import CSV pour les clients.
     */
    public function importCsv(Request $request): JsonResponse
    {
        // Récupérer les données avec le mapping déjà fait par le frontend
        $data = $request->input('data', []);
        $duplicateAction = $request->input('duplicate_action', 'update');
        
        if (empty($data)) {
            return response()->json(['message' => 'Aucune donnée à importer.'], 422);
        }

        // Obtenir le dernier numéro de compte utilisé avant de commencer l'importation
        $lastTier = Tier::whereNotNull('numero_compte')
            ->orderBy('numero_compte', 'desc')
            ->first();
        
        $nextNumber = 1;
        if ($lastTier) {
            // Extraire le numéro de la fin du numéro de compte existant
            $lastNumero = $lastTier->numero_compte;
            // Adapter l'expression régulière pour le nouveau format (0001, 0002, etc.)
            if (preg_match('/^(\d+)$/', $lastNumero, $matches)) {
                $nextNumber = (int)$matches[1] + 1;
            } else {
                // Si le format n'est pas reconnu, utiliser le nombre total de tiers + 1
                $nextNumber = Tier::count() + 1;
            }
        }

        $summary = ['created' => 0, 'updated' => 0, 'skipped' => 0, 'errors' => []];

        foreach ($data as $index => $item) {
            try {
                // Validation des données requises
                if (empty($item['nom_raison_sociale'])) {
                    $summary['errors'][] = sprintf('Ligne %d: Le nom ou la raison sociale est requis', $index + 1);
                    continue;
                }
                
                // Passer le numéro suivant à la fonction d'importation
                $result = $this->upsertTierFromImport($item, $duplicateAction, $nextNumber);
                
                // Incrémenter le numéro pour le prochain enregistrement si un nouveau client a été créé
                if ($result === 'created') {
                    $nextNumber++;
                }
                
                $summary[$result] = ($summary[$result] ?? 0) + 1;
            } catch (\Throwable $e) {
                $summary['errors'][] = sprintf('Ligne %d: %s', $index + 1, $e->getMessage());
            }
        }

        return response()->json($summary);
    }

    private function upsertTierFromImport(array $data, string $duplicateAction, int $nextNumber): string
    {
        // Normaliser les données d'importation
        $data = $this->normalizeImportedRow($data);
        
        // Validation des données requises
        if (empty($data['nom_raison_sociale'])) {
            throw new \InvalidArgumentException('Le nom ou la raison sociale est requis');
        }

        $tier = null;
        if (!empty($data['numero_compte'])) {
            $tier = Tier::where('numero_compte', $data['numero_compte'])->first();
        }
        if (!$tier && !empty($data['nom_raison_sociale'])) {
            $tier = Tier::where('nom_raison_sociale', $data['nom_raison_sociale'])->first();
        }

        // Si on trouve un enregistrement existant et que l'action est 'skip', on le saute
        if ($tier && $duplicateAction === 'skip') {
            return 'skipped';
        }

        // Générer un numéro de compte unique si non fourni
        $numeroCompte = $data['numero_compte'] ?? null;
        if (empty($numeroCompte)) {
            // Utiliser le numéro fourni par l'importation au lieu de générer un nouveau
            $numeroCompte = str_pad($nextNumber, 4, '0', STR_PAD_LEFT);
        } else {
            // S'assurer que le numéro fourni respecte la limite de 4 caractères
            if (strlen($numeroCompte) > 4) {
                $numeroCompte = substr($numeroCompte, 0, 4);
            }
        }

        // Déterminer le type de tiers (Client par défaut)
        $typeTiers = 'Client';
        if (!empty($data['type_tiers'])) {
            $typeTiers = in_array($data['type_tiers'], ['Client', 'Fournisseur']) ? $data['type_tiers'] : 'Client';
        }

        // Vérifier et normaliser la catégorie
        $categorie = $data['categorie'] ?? self::CATEGORIES[0];
        if (!in_array($categorie, self::CATEGORIES)) {
            // Si la catégorie n'est pas valide, utiliser le mapping ou la première par défaut
            $categoryMap = [
                'IND=STE' => 'Sté Privées Hors Grp',
                'HGP' => 'Sté Privées Hors Grp',
                'ADM' => 'Administration',
                'COL LOC' => 'Collectivité locale',
                'ONG' => 'Société de financement',
                'IND' => 'Individuel',
                'PG' => 'Personnel Groupe'
            ];
            
            $mappedCategory = null;
            // Recherche exacte
            if (isset($categoryMap[$categorie])) {
                $mappedCategory = $categoryMap[$categorie];
            } else {
                // Recherche partielle
                foreach ($categoryMap as $key => $value) {
                    if (stripos($categorie, $key) !== false) {
                        $mappedCategory = $value;
                        break;
                    }
                }
            }
            
            $categorie = $mappedCategory ?? self::CATEGORIES[0];
        }

        $tierPayload = [
            'numero_compte' => $numeroCompte,
            'nom_raison_sociale' => $data['nom_raison_sociale'],
            'bp' => $data['bp'] ?? '',
            'ville' => $data['ville'] ?? '',
            'pays' => $data['pays'] ?? 'Cameroun', // Valeur par défaut
            'adresse_geo_1' => $data['adresse_geo_1'] ?? '', // Valeur par défaut vide au lieu de null
            'adresse_geo_2' => $data['adresse_geo_2'] ?? '',
            'telephone' => $data['telephone'] ?? '',
            'email' => $data['email'] ?? '',
            'categorie' => $categorie,
            'n_contribuable' => $data['n_contribuable'] ?? '',
            'type_tiers' => $typeTiers,
        ];

        if ($tier) {
            // Pour les enregistrements existants, ne pas modifier le numéro de compte existant
            unset($tierPayload['numero_compte']);
            $tier->update($tierPayload);
            $this->persistDemandeFromImport($tier->id, $data, false);
            return 'updated';
        }

        $newTier = Tier::create($tierPayload);
        $this->persistDemandeFromImport($newTier->id, $data, true);
        
        // Enregistrer l'activité de création pour l'historique
        try {
            TierActivity::create([
                'tier_id' => $newTier->id,
                'user_id' => optional(Auth::user())->id,
                'action' => 'Création',
                'changes' => null,
            ]);
        } catch (\Throwable $e) {
            // ignore logging failures
        }
        
        return 'created';
    }

    private function persistDemandeFromImport(int $tierId, array $data, bool $isCreation): void
    {
        if (empty($this->demandeColumns)) {
            return;
        }

        // Normaliser les données avant de les insérer
        $data = $this->normalizeImportedRow($data);

        $demande = DB::table('demande_ouverture_compte')
            ->where('demande_ouverture_compte.id', $tierId) // Specify table name to avoid ambiguity
            ->first();
        
        // Construire le payload pour la demande d'ouverture de compte
        $payload = [];
        if ($isCreation && $this->hasDemandeColumn('id')) {
            $payload['id'] = $tierId;
        }
        
        // Mapper les champs de la demande
        if (isset($data['date_creation'])) {
            $payload = $this->assignDemandeValue($payload, 'date_creation', ['date_creation' => $data['date_creation']], $demande, $isCreation ? now() : null);
        } else {
            // Si aucune date de création n'est fournie, utiliser la date d'aujourd'hui
            $payload['date_creation'] = now()->format('Y-m-d');
        }
        
        if (isset($data['montant_facture'])) {
            $payload = $this->assignDemandeValue($payload, 'montant_facture', ['montant_facture' => $data['montant_facture']], $demande);
        }
        
        if (isset($data['montant_paye'])) {
            $payload = $this->assignDemandeValue($payload, 'montant_paye', ['montant_paye' => $data['montant_paye']], $demande);
        }
        
        if (isset($data['credit'])) {
            $payload = $this->assignDemandeValue($payload, 'credit', ['credit' => $data['credit']], $demande);
        }
        
        if (isset($data['motif'])) {
            $payload = $this->assignDemandeValue($payload, 'motif', ['motif' => $data['motif']], $demande);
        }
        
        // Handle agency information properly for imports
        if (Schema::hasTable('agence')) {
            // Check if we have agency fields in the imported data
            $hasAgencyInfo = !empty($data['etablissement']) || !empty($data['service']) || !empty($data['nom_signataire']);
            
            if ($hasAgencyInfo) {
                // Find or create the agency
                $agence = Agence::firstOrCreate(
                    [
                        'etablissement' => $data['etablissement'] ?? '',
                        'service' => $data['service'] ?? null,
                        'nom_signataire' => $data['nom_signataire'] ?? null
                    ],
                    [
                        'etablissement' => $data['etablissement'] ?? '',
                        'service' => $data['service'] ?? null,
                        'nom_signataire' => $data['nom_signataire'] ?? null
                    ]
                );
                
                // Add agence_id to payload if the column exists
                if ($this->hasDemandeColumn('agence_id')) {
                    $payload['agence_id'] = $agence->id;
                }
            } else if ($demande && !empty($demande->agence_id)) {
                // Keep existing agence_id if no new agency info provided
                $payload['agence_id'] = $demande->agence_id;
            }
        } else {
            // Fallback to direct fields if agence table doesn't exist
            if (isset($data['etablissement'])) {
                $payload = $this->assignDemandeValue($payload, 'etablissement', ['etablissement' => $data['etablissement']], $demande);
            }
            
            if (isset($data['service'])) {
                $payload = $this->assignDemandeValue($payload, 'service', ['service' => $data['service']], $demande);
            }
            
            if (isset($data['nom_signataire'])) {
                $payload = $this->assignDemandeValue($payload, 'nom_signataire', ['nom_signataire' => $data['nom_signataire']], $demande);
            }
        }
        
        if ($isCreation && $this->hasDemandeColumn('created_at')) {
            $payload['created_at'] = now();
        }
        if ($this->hasDemandeColumn('updated_at')) {
            $payload['updated_at'] = now();
        }

        $this->applyDemandeUser($payload);

        if (!$this->shouldPersistDemande($payload)) {
            return;
        }

        if ($demande) {
            unset($payload['id']);
            DB::table('demande_ouverture_compte')
                ->where('demande_ouverture_compte.id', $tierId) // Specify table name to avoid ambiguity
                ->update($payload);
        } else {
            DB::table('demande_ouverture_compte')->insert($payload);
        }
    }

    private function normalizeImportedRow(array $row): array
    {
        $normalized = [];
        foreach ($row as $key => $value) {
            if (is_string($value)) {
                $value = trim($value);
            }
            $normalized[$key] = $value;
        }

        // Mapping des catégories selon les spécifications
        if (isset($normalized['categorie'])) {
            $categoryMap = [
                'IND=STE' => 'Sté Privées Hors Grp',
                'HGP' => 'Sté Privées Hors Grp',
                'ADM' => 'Administration',
                'COL LOC' => 'Collectivité locale',
                'ONG' => 'Société de financement',
                'IND' => 'Individuel',
                'PG' => 'Personnel Groupe'
            ];
            
            $originalCategory = $normalized['categorie'];
            $mappedCategory = null;
            
            // Recherche exacte
            if (isset($categoryMap[$originalCategory])) {
                $mappedCategory = $categoryMap[$originalCategory];
            } else {
                // Recherche partielle
                foreach ($categoryMap as $key => $value) {
                    if (stripos($originalCategory, $key) !== false) {
                        $mappedCategory = $value;
                        break;
                    }
                }
            }
            
            // Si aucune correspondance n'a été trouvée, utiliser la catégorie telle quelle
            // mais vérifier qu'elle est dans les catégories valides
            if ($mappedCategory) {
                $normalized['categorie'] = $mappedCategory;
            } else if (!in_array($normalized['categorie'], self::CATEGORIES)) {
                // Si la catégorie n'est pas valide, utiliser la première par défaut
                $normalized['categorie'] = self::CATEGORIES[0];
            }
        }

        $normalized['date_creation'] = $this->parseDateValue($normalized['date_creation'] ?? null);
        $normalized['montant_facture'] = $this->parseNumeric($normalized['montant_facture'] ?? null);
        $normalized['montant_paye'] = $this->parseNumeric($normalized['montant_paye'] ?? null);
        $normalized['credit'] = $this->parseNumeric($normalized['credit'] ?? null);

        if (!empty($normalized['type_tiers'])) {
            $normalized['type_tiers'] = ucfirst(strtolower($normalized['type_tiers']));
        }

        return $normalized;
    }

    private function parseNumeric($value): ?float
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (is_numeric($value)) {
            return (float) $value;
        }
        $clean = str_replace([' ', "\u{00A0}"], '', (string) $value);
        $clean = str_replace(',', '.', $clean);
        return is_numeric($clean) ? (float) $clean : null;
    }

    private function parseDateValue(?string $value): ?string
    {
        if (!$value) {
            return null;
        }
        $value = trim($value);
        $formats = ['Y-m-d', 'd/m/Y', 'd-m-Y', 'm/d/Y', 'd.m.Y'];
        foreach ($formats as $format) {
            try {
                $dt = Carbon::createFromFormat($format, $value);
                if ($dt !== false) {
                    return $dt->format('Y-m-d');
                }
            } catch (\Throwable $e) {
                // ignore
            }
        }
        try {
            return Carbon::parse($value)->format('Y-m-d');
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function detectDelimiter(string $contents): string
    {
        $comma = substr_count($contents, ',');
        $semicolon = substr_count($contents, ';');
        return $semicolon > $comma ? ';' : ',';
    }

    private function normalizeHeader(?string $header): ?string
    {
        if ($header === null) {
            return null;
        }
        $normalized = strtolower(trim(Str::ascii($header)));
        
        // Mapping des colonnes selon les spécifications fournies
        if (strpos($normalized, 'nom') !== false && strpos($normalized, 'tiers') !== false) {
            return 'nom_raison_sociale';
        } else if ($normalized === 'type') {
            return 'categorie';
        } else if (strpos($normalized, 'adresse') !== false && strpos($normalized, 'geo') !== false) {
            return 'adresse_geo_1';
        } else if ($normalized === 'bp' || strpos($normalized, 'boite') !== false) {
            return 'bp';
        } else if ($normalized === 'ville') {
            return 'ville';
        } else if ($normalized === 'telephone' || $normalized === 'tel') {
            return 'telephone';
        } else if (strpos($normalized, 'date') !== false && strpos($normalized, 'creation') !== false) {
            return 'date_creation';
        } else if (strpos($normalized, 'signataire') !== false) {
            return 'nom_signataire';
        }
        
        return match ($normalized) {
            'nom', 'raison sociale', 'nom client', 'nom ou raison sociale', 'client' => 'nom_raison_sociale',
            'numero', 'numero compte', 'numero_compte' => 'numero_compte',
            'bp', 'boite postale' => 'bp',
            'ville' => 'ville',
            'pays' => 'pays',
            'adresse 1', 'adresse geo 1', 'adresse_geographique_1' => 'adresse_geo_1',
            'adresse 2', 'adresse geo 2', 'adresse_geographique_2' => 'adresse_geo_2',
            'telephone', 'tel' => 'telephone',
            'email', 'e-mail' => 'email',
            'categorie', 'catégorie', 'type client' => 'categorie',
            'n contribuable', 'numero contribuable' => 'n_contribuable',
            'type', 'type tiers', 'type_tiers' => 'type_tiers',
            'date creation', 'date_creation' => 'date_creation',
            'montant facture' => 'montant_facture',
            'montant paye', 'montant payé' => 'montant_paye',
            'credit', 'crédit' => 'credit',
            'motif' => 'motif',
            'etablissement' => 'etablissement',
            'service' => 'service',
            'nom signataire', 'nom du signataire' => 'nom_signataire',
            default => null,
        };
    }

    /**
     * Retourne la liste des agences (Établissement / Service / Nom du signataire).
     */
    public function agences(): JsonResponse
    {
        if (!Schema::hasTable('agence')) {
            return response()->json([], 200, [], JSON_UNESCAPED_UNICODE);
        }

        $columns = Schema::getColumnListing('agence');
        $select = array_values(array_intersect($columns, ['id', 'code', 'etablissement', 'service', 'nom_signataire', 'societe']));
        if (empty($select)) {
            $select = ['id'];
        }

        $query = DB::table('agence')->select($select);
        if (in_array('etablissement', $select, true)) {
            $query->orderBy('etablissement');
        }

        $rows = $query->get();
        return response()->json($rows, 200, [], JSON_UNESCAPED_UNICODE);
    }

    /**
     * Historique des clients - Affiche uniquement la dernière activité pour l'affichage dans l'interface.
     */
    public function historique(Request $request): JsonResponse
    {
        // Vérifier que l'utilisateur a la permission de gérer les clients en attente (admins uniquement)
        $user = Auth::user();
        \Log::info('Historique request', [
            'user_id' => $user ? $user->id : null,
            'user_permissions' => $user ? $user->getPermissions() : null,
            'has_manage_pending_clients' => $user ? $user->hasPermission('manage_pending_clients') : false
        ]);
        
        if (!$user || !$user->hasPermission('manage_pending_clients')) {
            \Log::warning('Unauthorized access to historique', [
                'user_id' => $user ? $user->id : null,
                'user_role' => $user ? $user->role : null
            ]);
            
            return response()->json(['message' => 'Accès non autorisé'], 403);
        }
        
        $type = $request->get('type'); // 'client' or 'mois'
        $nom = $request->get('nom_raison_sociale');
        $month = $request->get('month'); // YYYY-MM
        
        \Log::info('Historique parameters', [
            'type' => $type,
            'nom' => $nom,
            'month' => $month
        ]);

        // Objectif: retourner TOUS les tiers, avec la dernière activité et l'utilisateur associé
        $query = Tier::query()
            ->with(['latestActivity.user:id,username'])
            ->select(['tiers.id','tiers.numero_compte','tiers.nom_raison_sociale']); // Specify table name to avoid ambiguity

        if ($type === 'client' && $nom) {
            $query->where('tiers.nom_raison_sociale', 'like', "%$nom%"); // Specify table name to avoid ambiguity
        }

        if ($type === 'mois' && $month && preg_match('/^\\d{4}-\\d{2}$/', $month)) {
            // Filtrer par mois en utilisant tier_activities
            $parts = explode('-', $month);
            $yyyy = (int)($parts[0] ?? date('Y'));
            $mm = (int)($parts[1] ?? date('m'));
            $lastDay = cal_days_in_month(CAL_GREGORIAN, $mm, $yyyy);
            $start = sprintf('%04d-%02d-01', $yyyy, $mm);
            $end = sprintf('%04d-%02d-%02d', $yyyy, $mm, $lastDay);
            
            // Filtrer par les tiers qui ont des activités dans ce mois
            $query->whereHas('activities', function($q) use ($start, $end) {
                $q->whereBetween('created_at', [$start, $end]);
            });
        }

        try {
            $tiers = $query->get();
            \Log::info('Tiers fetched', ['count' => $tiers->count()]);
        } catch (\Exception $e) {
            \Log::error('Error fetching tiers', ['error' => $e->getMessage()]);
            return response()->json(['message' => 'Erreur lors du chargement des clients'], 500);
        }

        $mapped = $tiers->map(function($t) {
            // Récupérer la dernière activité et l'utilisateur associé
            $act = $t->latestActivity; // peut être null
            $action = $act?->action ?? 'Création';
            $user = $act?->user; // peut être null
            $displayUser = $user?->username ?? null;
            $originalCreator = null;
            
            // Vérifier si nous avons des informations sur le créateur original
            if ($act && $act->changes && isset($act->changes['original_creator']['username'])) {
                $originalCreator = $act->changes['original_creator']['username'];
            }
            
            // La date est toujours celle de la dernière activité
            // Si aucune activité n'existe, utiliser la date de création du client
            if ($act && $act->created_at) {
                $date = $act->created_at->toDateTimeString();
            } else {
                // Pour les clients sans activité, utiliser la date de création du client
                $firstActivity = $t->activities()->oldest()->first();
                if ($firstActivity && $firstActivity->created_at) {
                    $date = $firstActivity->created_at->toDateTimeString();
                } else {
                    // Utiliser la date de création du client si disponible
                    $date = $t->created_at ? $t->created_at->toDateTimeString() : now()->toDateTimeString();
                }
            }
            
            // Récupérer les changements s'il y en a
            $changes = $act?->changes ?? null;
            
            return [
                'date' => (string)$date,
                'nom_raison_sociale' => $t->nom_raison_sociale,
                'numero_compte' => $t->numero_compte,
                'action' => $action,
                'username' => $displayUser,
                'original_creator' => $originalCreator,
                'changes' => $changes, // Ajout des changements
            ];
        })
        // trier par la date calculée décroissante (plus récent en premier)
        ->sortByDesc(function($row) {
            return $row['date'] ?? '';
        })
        ->values();
        
        \Log::info('Historique response', ['activities_count' => $mapped->count()]);

        return response()->json($mapped, 200, [], JSON_UNESCAPED_UNICODE);
    }
    
    /**
     * Export des historiques clients - Retourne toutes les activités pour l'exportation avec le contenu complet de la grille.
     */
    public function exportHistorique(Request $request): JsonResponse
    {
        // Vérifier que l'utilisateur a la permission de gérer les clients en attente (admins uniquement)
        $user = Auth::user();
        if (!$user || !$user->hasPermission('manage_pending_clients')) {
            return response()->json(['message' => 'Accès non autorisé'], 403);
        }
        
        $type = $request->get('type'); // 'client' or 'mois'
        $nom = $request->get('nom_raison_sociale');
        $month = $request->get('month'); // YYYY-MM

        // Objectif: retourner TOUS les tiers, avec toutes les activités et les utilisateurs associés pour l'exportation
        $query = Tier::query()
            ->with(['activities.user:id,username'])
            ->select(['tiers.id','tiers.numero_compte','tiers.nom_raison_sociale']); // Specify table name to avoid ambiguity

        if ($type === 'client' && $nom) {
            $query->where('tiers.nom_raison_sociale', 'like', "%$nom%"); // Specify table name to avoid ambiguity
        }

        if ($type === 'mois' && $month && preg_match('/^\\d{4}-\\d{2}$/', $month)) {
            // Filtrer par mois en utilisant tier_activities
            $parts = explode('-', $month);
            $yyyy = (int)($parts[0] ?? date('Y'));
            $mm = (int)($parts[1] ?? date('m'));
            $lastDay = cal_days_in_month(CAL_GREGORIAN, $mm, $yyyy);
            $start = sprintf('%04d-%02d-01', $yyyy, $mm);
            $end = sprintf('%04d-%02d-%02d', $yyyy, $mm, $lastDay);
            
            // Filtrer par les tiers qui ont des activités dans ce mois
            $query->whereHas('activities', function($q) use ($start, $end) {
                $q->whereBetween('created_at', [$start, $end]);
            });
        }

        try {
            $tiers = $query->get();
        } catch (\Exception $e) {
            \Log::error('Error fetching tiers for export', ['error' => $e->getMessage()]);
            return response()->json(['message' => 'Erreur lors du chargement des clients pour l\'export'], 500);
        }

        // Collecter toutes les activités de tous les tiers avec leurs informations complètes
        $allActivities = collect();
        
        foreach ($tiers as $tier) {
            // Ajouter d'abord l'entrée principale du client (comme dans la grille)
            $latestActivity = $tier->latestActivity;
            $latestAction = $latestActivity?->action ?? 'Création';
            $latestUser = $latestActivity?->user; // peut être null
            $latestDisplayUser = $latestUser?->username ?? null;
            $latestOriginalCreator = null;
            
            // Vérifier si nous avons des informations sur le créateur original
            if ($latestActivity && $latestActivity->changes && isset($latestActivity->changes['original_creator']['username'])) {
                $latestOriginalCreator = $latestActivity->changes['original_creator']['username'];
            }
            
            // La date est toujours celle de la dernière activité
            // Si aucune activité n'existe, utiliser la date de création du client
            if ($latestActivity && $latestActivity->created_at) {
                $latestDate = $latestActivity->created_at->toDateTimeString();
            } else {
                // Pour les clients sans activité, utiliser la date de création du client
                $firstActivity = $tier->activities()->oldest()->first();
                if ($firstActivity && $firstActivity->created_at) {
                    $latestDate = $firstActivity->created_at->toDateTimeString();
                } else {
                    // Utiliser la date de création du client si disponible
                    $latestDate = $tier->created_at ? $tier->created_at->toDateTimeString() : now()->toDateTimeString();
                }
            }
            
            // Ajouter l'entrée principale du client
            $allActivities->push([
                'date' => (string)$latestDate,
                'nom_raison_sociale' => $tier->nom_raison_sociale,
                'numero_compte' => $tier->numero_compte,
                'action' => $latestAction,
                'username' => $latestDisplayUser,
                'original_creator' => $latestOriginalCreator,
                'changes' => $latestActivity?->changes ?? null,
                'is_summary_row' => true, // Indicateur pour distinguer les lignes récapitulatives
            ]);
            
            // Ajouter ensuite toutes les activités individuelles du client
            foreach ($tier->activities as $activity) {
                $user = $activity->user; // peut être null
                $displayUser = $user?->username ?? null;
                $originalCreator = null;
                
                // Vérifier si nous avons des informations sur le créateur original
                if ($activity->changes && isset($activity->changes['original_creator']['username'])) {
                    $originalCreator = $activity->changes['original_creator']['username'];
                }
                
                // La date est toujours celle de l'activité
                // Si aucune activité n'existe, utiliser la date de création du client
                if ($activity->created_at) {
                    $date = $activity->created_at->toDateTimeString();
                } else {
                    // Pour les clients sans activité, utiliser la date de création du client
                    $firstActivity = $tier->activities()->oldest()->first();
                    if ($firstActivity && $firstActivity->created_at) {
                        $date = $firstActivity->created_at->toDateTimeString();
                    } else {
                        // Utiliser la date de création du client si disponible
                        $date = $tier->created_at ? $tier->created_at->toDateTimeString() : now()->toDateTimeString();
                    }
                }
                
                // Récupérer les changements s'il y en a
                $changes = $activity->changes ?? null;
                
                $allActivities->push([
                    'date' => (string)$date,
                    'nom_raison_sociale' => $tier->nom_raison_sociale,
                    'numero_compte' => $tier->numero_compte,
                    'action' => $activity->action,
                    'username' => $displayUser,
                    'original_creator' => $originalCreator,
                    'changes' => $changes,
                    'is_summary_row' => false, // Indicateur pour distinguer les lignes détaillées
                ]);
            }
        }

        // Trier TOUTES les données par date décroissante (plus récent en premier)
        // Tous types d'actions confondus (création et modification)
        $sortedActivities = $allActivities->sortByDesc(function($row) {
            return $row['date'] ?? '';
        })->values();

        return response()->json($sortedActivities, 200, [], JSON_UNESCAPED_UNICODE);
    }

    /**
     * Export complet des clients - Retourne tous les clients avec les informations de demande d'ouverture de compte et agence.
     */
    public function exportWithDetails(Request $request): JsonResponse
    {
        $query = DB::table('tiers')
            ->select([
                'tiers.id',
                'tiers.numero_compte',
                'tiers.nom_raison_sociale',
                'tiers.bp',
                'tiers.ville',
                'tiers.pays',
                'tiers.adresse_geo_1',
                'tiers.adresse_geo_2',
                'tiers.telephone',
                'tiers.email',
                'tiers.categorie',
                'tiers.n_contribuable',
                'tiers.type_tiers'
            ]);
            
        // Add demande_ouverture_compte fields if the table exists
        if (Schema::hasTable('demande_ouverture_compte')) {
            $query->leftJoin('demande_ouverture_compte', 'tiers.id', '=', 'demande_ouverture_compte.id')
                  ->addSelect([
                    'demande_ouverture_compte.date_creation as date_creation_demande',
                    'demande_ouverture_compte.montant_facture',
                    'demande_ouverture_compte.montant_paye',
                    'demande_ouverture_compte.credit',
                    'demande_ouverture_compte.motif as demande_motif'
                  ]);
            
            // Add agence fields if agence table exists and agence_id column exists
            if (Schema::hasTable('agence') && Schema::hasColumn('demande_ouverture_compte', 'agence_id')) {
                $query->leftJoin('agence', 'demande_ouverture_compte.agence_id', '=', 'agence.id')
                      ->addSelect([
                        'agence.etablissement',
                        'agence.service',
                        'agence.nom_signataire'
                      ]);
            }
        }
        
        // Recherche

        // Recherche
        if ($search = trim((string) $request->get('search', ''))) {
            $query->where(function ($q) use ($search) {
                $q->where('tiers.numero_compte', 'like', "%{$search}%")
                  ->orWhere('tiers.nom_raison_sociale', 'like', "%{$search}%")
                  ->orWhere('tiers.bp', 'like', "%{$search}%")
                  ->orWhere('tiers.ville', 'like', "%{$search}%")
                  ->orWhere('tiers.pays', 'like', "%{$search}%")
                  ->orWhere('tiers.categorie', 'like', "%{$search}%");
            });
        }

        // Filtrage par type_tiers
        $typeTiersFilter = $request->input('type_tiers');
        if (!empty($typeTiersFilter)) {
            $query->where('tiers.type_tiers', $typeTiersFilter);
        }

        // Tri
        $sortRequest = (string) $request->get('sort', 'tiers.nom_raison_sociale');
        $direction = strtolower((string) $request->get('dir', 'asc')) === 'desc' ? 'desc' : 'asc';

        $allowedSorts = [
            'numero_compte' => 'tiers.numero_compte',
            'nom_raison_sociale' => 'tiers.nom_raison_sociale',
            'bp' => 'tiers.bp',
            'ville' => 'tiers.ville',
            'pays' => 'tiers.pays',
            'categorie' => 'tiers.categorie',
            'type_tiers' => 'tiers.type_tiers',
        ];

        if (!array_key_exists($sortRequest, $allowedSorts)) {
            $sortRequest = 'tiers.nom_raison_sociale';
        }

        $query->orderBy($allowedSorts[$sortRequest], $direction);

        // Limiter le nombre de résultats pour l'export
        $perPage = max(1, min((int) $request->get('per_page', 1000), 10000));
        $results = $query->paginate($perPage);

        // Traitement des résultats pour combiner les champs provenant de différentes tables
        $collection = $results->getCollection()->map(function ($row) {
            return [
                'id' => $row->id,
                'numero_compte' => $row->numero_compte,
                'nom_raison_sociale' => $row->nom_raison_sociale,
                'bp' => $row->bp,
                'ville' => $row->ville,
                'pays' => $row->pays,
                'adresse_geo_1' => $row->adresse_geo_1,
                'adresse_geo_2' => $row->adresse_geo_2,
                'telephone' => $row->telephone,
                'email' => $row->email,
                'categorie' => $row->categorie,
                'n_contribuable' => $row->n_contribuable,
                'type_tiers' => $row->type_tiers,
                // Utiliser les données de demande_ouverture_compte si disponibles
                'date_creation' => $row->date_creation_demande,
                'montant_facture' => $row->montant_facture,
                'montant_paye' => $row->montant_paye,
                'credit' => $row->credit,
                'motif' => $row->demande_motif,
                // Utiliser les données de agence si disponibles
                'etablissement' => $row->etablissement,
                'service' => $row->service,
                'nom_signataire' => $row->nom_signataire,
            ];
        });

        $results->setCollection($collection);

        return response()->json([
            'data' => $results->items(),
            'current_page' => $results->currentPage(),
            'last_page' => $results->lastPage(),
            'per_page' => $results->perPage(),
            'total' => $results->total(),
        ], 200, [], JSON_UNESCAPED_UNICODE);
    }

    /**
     * Génère le prochain numéro de compte disponible.
     */
    private function generateNextAccountNumber(): string
    {
        // Trouver le dernier numéro de compte existant
        $lastTier = Tier::whereNotNull('numero_compte')
            ->orderBy('numero_compte', 'desc')
            ->first();
        
        $nextNumber = 1;
        if ($lastTier) {
            // Extraire le numéro de la fin du numéro de compte existant
            $lastNumero = $lastTier->numero_compte;
            // Adapter l'expression régulière pour le nouveau format (0001, 0002, etc.)
            if (preg_match('/^(\d+)$/', $lastNumero, $matches)) {
                $nextNumber = (int)$matches[1] + 1;
            } else {
                // Si le format n'est pas reconnu, utiliser le nombre total de tiers + 1
                $nextNumber = Tier::count() + 1;
            }
        }
        
        // Générer un nouveau numéro de compte avec le format souhaité (0001, 0002, etc.)
        $accountNumber = str_pad($nextNumber, 4, '0', STR_PAD_LEFT);
        
        // Vérifier que le numéro est unique, sinon en générer un nouveau
        while (Tier::where('numero_compte', $accountNumber)->exists()) {
            $nextNumber++;
            $accountNumber = str_pad($nextNumber, 4, '0', STR_PAD_LEFT);
        }
        
        return $accountNumber;
    }

    /**
     * Affiche un aperçu d'impression pour un client (tier).
     */
    public function preview(Tier $tier)
    {
        // Récupère les informations de la demande d'ouverture de compte si elles existent
        $demandeQuery = DB::table('demande_ouverture_compte')
            ->where('demande_ouverture_compte.id', $tier->id); // Specify table name to avoid ambiguity
        
        // Join with agence table if it exists and agence_id column exists
        if (Schema::hasTable('agence') && in_array('agence_id', $this->demandeColumns)) {
            $demandeQuery->leftJoin('agence', 'demande_ouverture_compte.agence_id', '=', 'agence.id');
        }
        
        $demande = $demandeQuery->first();
        
        $signatureDate = $demande && $demande->date_creation
            ? Carbon::parse($demande->date_creation)->format('d/m/Y')
            : Carbon::now()->format('d/m/Y');
            
        // Get organization settings
        $organizationSetting = OrganizationSetting::first();
        $companyName = $organizationSetting ? $organizationSetting->name : 'CFAO MOBILITY CAMEROON';
        $companyLogo = $organizationSetting && $organizationSetting->logo ? url('storage/' . $organizationSetting->logo) : asset('images/LOGO.png');
            
        $pageData = [
            'tier' => $tier,
            'demande' => $demande,
            'signatureCity' => $tier->ville ?? 'DLA',
            'signatureDate' => $signatureDate,
            'purchaseTitle' => $demande->motif ?? '',
            'companyName' => $companyName,
            'companyLogo' => $companyLogo,
        ];

        return response()->view('clients.preview', [
            'pages' => [$pageData],
            'clientId' => $tier->id,
            'clientName' => $tier->nom_raison_sociale ?? '',
            'companyName' => $companyName,
            'companyLogo' => $companyLogo,
        ]);
    }
}