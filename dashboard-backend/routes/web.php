<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\TraitesController;
use App\Http\Controllers\TiersController;
use App\Http\Controllers\BrowsershotController;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Ces routes sont chargées par le RouteServiceProvider avec le middleware "web".
| Elles contiennent la protection CSRF.
|
*/

Route::get('/', function () {
    return view('welcome'); // Ou redirection vers votre app React
});

// --- ROUTES D'AFFICHAGE (Preview PDF/HTML) ---
// Attention : Sans cookies, ces routes ne sont pas protégées par Auth::user()
// Si vous avez besoin de protection, déplacez-les dans api.php et gérez le téléchargement en JS.

Route::get('/print/traites/{traite}/{index?}', [TraitesController::class, 'print'])
    ->whereNumber('index')
    ->name('traites.print');

Route::get('/print/traites/{traite}/preview', [TraitesController::class, 'preview'])
    ->name('traites.preview');

Route::get('/print/traites/{traite}/acceptance', [TraitesController::class, 'acceptancePreview'])
    ->name('traites.acceptance');

Route::get('/print/clients/{tier}/preview', [TiersController::class, 'preview'])
    ->name('clients.preview');

Route::get('/print/traites/{traite}/preview.pdf', [TraitesController::class, 'previewPdf'])
    ->name('traites.preview_pdf');

// Route de diagnostic Browsershot (Test local uniquement)
Route::get('/test/browsershot', function() {
    // ... votre code de test existant ...
});