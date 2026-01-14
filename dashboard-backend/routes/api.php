<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\DatabaseController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\TraitesStatsController;
use App\Http\Controllers\TraitesController;
use App\Http\Controllers\TiersController;
use App\Http\Controllers\ClientStatsController;
use App\Http\Controllers\Api\UserController;
use App\Http\Controllers\PendingClientsController;
use App\Http\Controllers\ClientApprovalHistoryController;

Route::post('/login', [AuthController::class, 'login']);

// Routes pour la gestion des utilisateurs AD
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/users/ad/check', [UserManagementController::class, 'checkAdUser']);
    Route::post('/users/ad/create', [UserManagementController::class, 'createAdUser']);
});
Route::post('/logout', [AuthController::class, 'logout'])->middleware('auth:sanctum');
Route::get('/user', [AuthController::class, 'user'])->middleware('auth:sanctum');

// Test Routes
Route::get('/test-cors', function() {
    return response()->json(['message' => 'CORS fonctionne !']);
});

// User management
Route::prefix('users')->group(function () {
    Route::get('/', [UserController::class, 'index'])->middleware('auth:sanctum');
    Route::post('/', [UserController::class, 'store'])->middleware('auth:sanctum');
    Route::get('/{id}', [UserController::class, 'show'])->middleware('auth:sanctum');
    Route::put('/{id}', [UserController::class, 'update'])->middleware('auth:sanctum');
    Route::delete('/{id}', [UserController::class, 'destroy'])->middleware('auth:sanctum');
    Route::get('/{id}/permissions', [UserController::class, 'getUserPermissions'])->middleware('auth:sanctum');
    Route::put('/{id}/permissions', [UserController::class, 'updateUserPermissions'])->middleware('auth:sanctum');
});

// Notifications
Route::prefix('user')->group(function () {
    Route::get('/notifications', [UserController::class, 'getNotifications'])->middleware('auth:sanctum');
    Route::post('/notifications/{id}/read', [UserController::class, 'markNotificationAsRead'])->middleware('auth:sanctum');
});

Route::get('/permissions', [UserController::class, 'getPermissions'])->middleware('auth:sanctum');

// Organization & Stats
Route::prefix('organization')->group(function () {
    Route::get('/settings', [UserController::class, 'getOrganizationSettings'])->middleware('auth:sanctum');
    Route::put('/settings', [UserController::class, 'updateOrganizationSettings'])->middleware('auth:sanctum');
});

Route::get('/traites/stats', [TraitesStatsController::class, 'stats']);
Route::get('/traites/monthly', [TraitesStatsController::class, 'monthly']);
Route::get('/traites/status', [TraitesStatsController::class, 'statusBreakdown']);
Route::get('/traites/available-years', [TraitesStatsController::class, 'availableYears']);
Route::get('/traites/external-count', [TraitesStatsController::class, 'externalCount']);

// Tiers / Clients
Route::get('/tiers', [TiersController::class, 'index']);
Route::post('/tiers', [TiersController::class, 'store'])->middleware('auth:sanctum');
Route::post('/tiers/import-csv', [TiersController::class, 'importCsv'])->middleware('auth:sanctum');
Route::get('/agences', [TiersController::class, 'agences'])->middleware('auth:sanctum');
Route::get('/tiers/historique', [TiersController::class, 'historique'])->middleware('auth:sanctum');
Route::get('/tiers/export-historique', [TiersController::class, 'exportHistorique'])->middleware('auth:sanctum');
Route::get('/tiers/export-with-details', [TiersController::class, 'exportWithDetails'])->middleware('auth:sanctum');
Route::get('/tiers/{tier}', [TiersController::class, 'show']);
Route::put('/tiers/{tier}', [TiersController::class, 'update'])->middleware('auth:sanctum');
Route::delete('/tiers/{tier}', [TiersController::class, 'destroy'])->middleware('auth:sanctum');

// Traites
Route::get('/traites/historique', [TraitesController::class, 'historique']);
Route::get('/traites/export-historique', [TraitesController::class, 'exportHistorique']);
Route::get('/traites/export-with-details', [TraitesController::class, 'exportWithDetails'])->middleware('auth:sanctum');
Route::get('/traites', [TraitesController::class, 'index']);
Route::post('/traites', [TraitesController::class, 'store'])->middleware('auth:sanctum');
Route::post('/traites/import-csv', [TraitesController::class, 'importCsv']); 
Route::get('/traites/{traite}', [TraitesController::class, 'show']);
Route::put('/traites/{traite}', [TraitesController::class, 'update'])->middleware('auth:sanctum');
Route::delete('/traites/{traite}', [TraitesController::class, 'destroy'])->middleware('auth:sanctum');
Route::patch('/traites/{traite}/statut', [TraitesController::class, 'updateStatus'])->middleware('auth:sanctum');
Route::patch('/traites/{traite}/decision', [TraitesController::class, 'updateDecision'])->middleware('auth:sanctum');

// --- CORRECTION ICI : Ajout du middleware auth:sanctum ---
Route::prefix('clients')->group(function () {
    Route::get('/stats', [ClientStatsController::class, 'stats']);
    Route::get('/available-years', [ClientStatsController::class, 'availableYears']);
    Route::get('/monthly', [ClientStatsController::class, 'monthly']);
    Route::get('/type-breakdown', [ClientStatsController::class, 'typeBreakdown']);
    Route::get('/external-count', [ClientStatsController::class, 'externalCount']); // Add this line
    
    // IMPORTANT : Middleware ajouté ici
    Route::get('/approval-history', [ClientApprovalHistoryController::class, 'index'])
        ->middleware('auth:sanctum');
});

// Settings (Auth required)
Route::middleware('auth:sanctum')->group(function () {
    Route::get('/organization/settings', [UserController::class, 'getOrganizationSettings']);
    Route::post('/organization/settings', [UserController::class, 'updateOrganizationSettings']);
});

// Pending Clients (Auth required)
Route::prefix('pending-clients')->group(function () {
    Route::get('/', [PendingClientsController::class, 'index'])->middleware('auth:sanctum');
    Route::post('/', [PendingClientsController::class, 'store'])->middleware('auth:sanctum');
    Route::get('/{pendingClient}', [PendingClientsController::class, 'show'])->middleware('auth:sanctum');
    Route::put('/{pendingClient}', [PendingClientsController::class, 'update'])->middleware('auth:sanctum');
    Route::post('/{pendingClient}/submit', [PendingClientsController::class, 'submit'])->middleware('auth:sanctum');
    Route::delete('/{pendingClient}', [PendingClientsController::class, 'destroy'])->middleware('auth:sanctum');
    Route::post('/{pendingClient}/approve', [PendingClientsController::class, 'approve'])->middleware('auth:sanctum');
    Route::post('/{pendingClient}/reject', [PendingClientsController::class, 'reject'])->middleware('auth:sanctum');
});

// Dans routes/api.php (à ajouter dans le groupe auth:sanctum existant)

// Test de connexion DB (utile pour le diagnostic API)
Route::get('/test-db', function () {
    // ... votre code de test DB ...
});

// Envoi par email (Ce sont des actions API, donc api.php)
Route::post('/print/traites/{traite}/email', [TraitesController::class, 'emailPreview'])
    ->name('api.traites.email');

Route::post('/print/traites/{traite}/email-image', [TraitesController::class, 'emailPreviewImage'])
    ->name('api.traites.email_image');