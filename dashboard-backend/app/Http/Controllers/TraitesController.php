<?php

namespace App\Http\Controllers;

use App\Models\Traite;
use App\Models\TraiteActivity;
use App\Models\OrganizationSetting;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Barryvdh\DomPDF\Facade\Pdf;
// Browsershot (optionnel, pour rendu navigateur pixel-perfect)
// Installer le package spatie/browsershot pour activer cet import
// et avoir Node + Chrome/Chromium disponibles sur la machine
use Spatie\Browsershot\Browsershot;

class TraitesController extends Controller
{
    public function index(Request $request)
    {
        $query = Traite::query();

        // Recherche globale sur plusieurs colonnes
        if ($s = $request->get('search')) {
            $query->where(function($q) use ($s) {
                $q->where('numero', 'like', "%$s%")
                  ->orWhere('nom_raison_sociale', 'like', "%$s%")
                  ->orWhere('motif', 'like', "%$s%")
                  ->orWhere('domiciliation_bancaire', 'like', "%$s%")
                  ->orWhere('rib', 'like', "%$s%")
                  ->orWhere('commentaires', 'like', "%$s%")
                  ->orWhere('statut', 'like', "%$s%")
                  ->orWhere('origine_traite', 'like', "%$s%")
                  ->orWhereRaw('CAST(montant AS CHAR) like ?', ["%$s%"])
                  ->orWhereRaw('DATE_FORMAT(echeance, "%d-%m-%Y") like ?', ["%$s%"])
                  ->orWhereRaw('DATE_FORMAT(date_emission, "%d-%m-%Y") like ?', ["%$s%"]);
            });
        }

        // Filtre alphabétique par initiale de nom_raison_sociale
        if ($alpha = $request->get('alpha')) {
            $alpha = strtoupper(substr($alpha, 0, 1));
            if ($alpha === '#') {
                // Noms qui ne commencent pas par A-Z
                $query->where(function($q) {
                    $q->whereRaw("LEFT(UPPER(nom_raison_sociale), 1) < 'A'")
                      ->orWhereRaw("LEFT(UPPER(nom_raison_sociale), 1) > 'Z'");
                });
            } else if ($alpha >= 'A' && $alpha <= 'Z') {
                $query->whereRaw('LEFT(UPPER(nom_raison_sociale), 1) = ?', [$alpha]);
            }
        }

        // Filtres spécifiques: statut, plage d'échéance
        if ($statut = $request->get('statut')) {
            $query->where('statut', $statut);
        }
        
        // Filtre par origine_traite
        if ($origine_traite = $request->get('origine_traite')) {
            $query->where('origine_traite', $origine_traite);
        }
        $from = $request->get('from');
        $to = $request->get('to');
        if ($from || $to) {
            // Normaliser l'ordre des bornes si inversées
            if ($from && $to) {
                $fromTs = strtotime($from);
                $toTs = strtotime($to);
                if ($fromTs !== false && $toTs !== false && $fromTs > $toTs) {
                    [$from, $to] = [$to, $from];
                }
            }

            $query->where(function($qq) use ($from, $to) {
                if ($from) {
                    $qq->whereDate('date_emission', '>=', $from);
                }
                if ($to) {
                    $qq->whereDate('date_emission', '<=', $to);
                }
            });
        }

        // Nouvelle plage sur la colonne 'echeance'
        $echeanceFrom = $request->get('echeance_from');
        $echeanceTo = $request->get('echeance_to');
        if ($echeanceFrom || $echeanceTo) {
            if ($echeanceFrom && $echeanceTo) {
                $fromTs = strtotime($echeanceFrom);
                $toTs = strtotime($echeanceTo);
                if ($fromTs !== false && $toTs !== false && $fromTs > $toTs) {
                    [$echeanceFrom, $echeanceTo] = [$echeanceTo, $echeanceFrom];
                }
            }
            $query->where(function($qq) use ($echeanceFrom, $echeanceTo) {
                if ($echeanceFrom) {
                    $qq->whereDate('echeance', '>=', $echeanceFrom);
                }
                if ($echeanceTo) {
                    $qq->whereDate('echeance', '<=', $echeanceTo);
                }
            });
        }

        // Raccourci: upcoming_days = N => statut=Non échu + echeance in [today, today + (N-1)]
        if ($request->has('upcoming_days')) {
            $n = (int) $request->get('upcoming_days');
            if ($n > 0) {
                $today = date('Y-m-d');
                $end = date('Y-m-d', strtotime("+$n days")); // exclusive upper bound alternative
                // Utiliser bornes inclusives J..J+(N-1)
                $inclusiveEnd = date('Y-m-d', strtotime("+".($n-1)." days"));
                $query->where('statut', 'Non échu')
                      ->whereDate('echeance', '>=', $today)
                      ->whereDate('echeance', '<=', $inclusiveEnd);
            }
        }

        // Tri: par défaut par nom A->Z si alpha, sinon par date d'émission décroissante (plus récent en premier);
        // personnalisable via query params
        $sort = $request->get('sort');
        $dir = strtolower($request->get('dir', 'desc')) === 'asc' ? 'asc' : 'desc';
        $allowedSorts = ['echeance','date_emission','created_at','montant','numero','nom_raison_sociale','statut','id', 'origine_traite'];
        if (!in_array($sort, $allowedSorts, true)) {
            $sort = $request->has('alpha') ? 'nom_raison_sociale' : 'date_emission';
        }

        $perPage = (int) $request->get('per_page', 10);
        
        // Si c'est pour l'exportation (per_page élevé), retourner toutes les données sans pagination
        if ($perPage >= 1000) {
            // Tri numérique spécial pour le champ numero
            if ($sort === 'numero') {
                $allData = $query->orderByRaw("CAST(numero AS UNSIGNED) $dir")->get();
            } else {
                $allData = $query->orderBy($sort, $dir)->get();
            }
            return response()->json([
                'data' => $allData,
                'total' => $allData->count(),
                'per_page' => $allData->count(),
                'current_page' => 1,
                'last_page' => 1
            ], 200, [], JSON_UNESCAPED_UNICODE);
        }
        
        // Limitation normale pour la pagination
        if ($perPage < 1 || $perPage > 200) { $perPage = 10; }
        
        // Tri numérique spécial pour le champ numero
        if ($sort === 'numero') {
            return response()->json($query->orderByRaw("CAST(numero AS UNSIGNED) $dir")->paginate($perPage), 200, [], JSON_UNESCAPED_UNICODE);
        } else {
            return response()->json($query->orderBy($sort, $dir)->paginate($perPage), 200, [], JSON_UNESCAPED_UNICODE);
        }
    }

    /**
     * Render printable HTML for a specific traite and tranche index (1-based)
     */
    public function print(Traite $traite, ?int $index = 1)
    {
        $totalTranches = max(1, (int) ($traite->nombre_traites ?? 1));
        $currentIndex = min(max(1, (int) ($index ?? 1)), $totalTranches);

        // Base dates
        $emission = $traite->date_emission ? Carbon::parse($traite->date_emission) : null;
        $firstDue = $traite->echeance ? Carbon::parse($traite->echeance) : null;

        // Compute tranche due date: monthly increments from first échéance
        $dueDate = $firstDue ? $firstDue->copy()->addMonthsNoOverflow($currentIndex - 1) : null;

        // Amount per tranche: simple division (total / nombre_traites)
        $total = (int) round($traite->montant ?? 0);
        $amountForThisTranche = (int) round($total / max(1, $totalTranches));

        // French number to words (basic, integers)
        $amountInWords = $this->numberToFrenchWords($amountForThisTranche);

        // Get organization settings
        $organizationSetting = OrganizationSetting::first();
        $companyName = $organizationSetting ? $organizationSetting->name : 'CFAO MOBILITY CAMEROON';
        $companyLogo = $organizationSetting && $organizationSetting->logo ? url('storage/' . $organizationSetting->logo) : asset('images/LOGO.png');

        $data = [
            'rangeText' => $currentIndex . ' | ' . $totalTranches,
            'ville' => 'Douala', // Ensure ville is always set
            'date_emission' => $emission ? $emission->format('d/m/Y') : '',
            'echeance' => $dueDate ? $dueDate->format('d/m/Y') : '',
            'montant_tranche' => number_format($amountForThisTranche, 0, ',', ' '),
            'montant_tranche_words' => strtoupper($amountInWords),
            'nom_raison_sociale' => $traite->nom_raison_sociale ?? '',
            'domiciliation' => $traite->domiciliation_bancaire ?? '',
            'rib' => $traite->rib ?? '',
            'numero' => $traite->numero ?? '',
            'date_emission_text_long' => $emission ? $emission->locale('fr')->translatedFormat('d F Y') : '',
            'companyName' => $companyName,
            'companyLogo' => $companyLogo,
        ];

        return response()->view('traites.print', $data);
    }

    /**
     * Aperçu multi-pages pour toutes les traites (toutes tranches)
     */
    public function preview(Traite $traite)
    {
        $totalTranches = max(1, (int) ($traite->nombre_traites ?? 1));
        $emission = $traite->date_emission ? Carbon::parse($traite->date_emission) : null;
        $firstDue = $traite->echeance ? Carbon::parse($traite->echeance) : null;

        $total = (int) round($traite->montant ?? 0);

        // Get organization settings
        $organizationSetting = OrganizationSetting::first();
        $companyName = $organizationSetting ? $organizationSetting->name : 'CFAO MOBILITY CAMEROON';
        $companyLogo = $organizationSetting && $organizationSetting->logo ? url('storage/' . $organizationSetting->logo) : asset('images/LOGO.png');

        $pages = [];
        for ($i = 1; $i <= $totalTranches; $i++) {
            $dueDate = $firstDue ? $firstDue->copy()->addMonthsNoOverflow($i - 1) : null;
            $amountForThisTranche = (int) round($total / max(1, $totalTranches));
            $pages[] = [
                'rangeText' => $i . ' | ' . $totalTranches,
                'ville' => 'Douala', // Ensure ville is always set
                'date_emission' => $emission ? $emission->format('d/m/Y') : '',
                'echeance' => $dueDate ? $dueDate->format('d/m/Y') : '',
                'montant_tranche' => number_format($amountForThisTranche, 0, ',', ' '),
                'montant_tranche_words' => strtoupper($this->numberToFrenchWords($amountForThisTranche)),
                'nom_raison_sociale' => $traite->nom_raison_sociale ?? '',
                'domiciliation' => $traite->domiciliation_bancaire ?? '',
                'rib' => $traite->rib ?? '',
                'numero' => $traite->numero ?? '',
                'date_emission_text_long' => $emission ? $emission->locale('fr')->translatedFormat('d F Y') : '',
                'companyName' => $companyName,
                'companyLogo' => $companyLogo,
            ];
        }

        return response()->view('traites.preview', [ 
            'pages' => $pages, 
            'traiteId' => $traite->id, 
            'traiteNumero' => $traite->numero,
            'companyName' => $companyName,
            'companyLogo' => $companyLogo,
        ]);
    }

    /**
     * Retourne le PDF multi-pages (aperçu) en téléchargement
     */
    public function previewPdf(Traite $traite)
    {
        $totalTranches = max(1, (int) ($traite->nombre_traites ?? 1));
        $emission = $traite->date_emission ? Carbon::parse($traite->date_emission) : null;
        $firstDue = $traite->echeance ? Carbon::parse($traite->echeance) : null;
        $total = (int) round($traite->montant ?? 0);

        // Get organization settings
        $organizationSetting = OrganizationSetting::first();
        $companyName = $organizationSetting ? $organizationSetting->name : 'CFAO MOBILITY CAMEROON';
        $companyLogo = $organizationSetting && $organizationSetting->logo ? url('storage/' . $organizationSetting->logo) : asset('images/LOGO.png');

        // Construire un HTML "pur impression" en utilisant traites.print, sans toolbar/footer
        $htmlParts = [];
        for ($i = 1; $i <= $totalTranches; $i++) {
            $dueDate = $firstDue ? $firstDue->copy()->addMonthsNoOverflow($i - 1) : null;
            $amountForThisTranche = (int) round($total / max(1, $totalTranches));
            $data = [
                'rangeText' => $i . ' | ' . $totalTranches,
                'ville' => 'Douala', // Ensure ville is always set
                'date_emission' => $emission ? $emission->format('d/m/Y') : '',
                'echeance' => $dueDate ? $dueDate->format('d/m/Y') : '',
                'montant_tranche' => number_format($amountForThisTranche, 0, ',', ' '),
                'montant_tranche_words' => strtoupper($this->numberToFrenchWords($amountForThisTranche)),
                'nom_raison_sociale' => $traite->nom_raison_sociale ?? '',
                'domiciliation' => $traite->domiciliation_bancaire ?? '',
                'rib' => $traite->rib ?? '',
                'numero' => $traite->numero ?? '',
                'date_emission_text_long' => $emission ? $emission->locale('fr')->translatedFormat('d F Y') : '',
                'companyName' => $companyName,
                'companyLogo' => $companyLogo,
            ];
            $htmlParts[] = view('traites.print', $data)->render();
            if ($i < $totalTranches) {
                $htmlParts[] = '<div style="page-break-after: always;"></div>';
            }
        }
        $html = implode("\n", $htmlParts);
        $pdf = Pdf::loadHTML($html)->setPaper('a4');
        return $pdf->download('traites_'.$traite->id.'.pdf');
    }

    /**
     * Capture "impression" via navigateur (Browsershot) sans interaction utilisateur
     */
    public function previewPdfCapture(Traite $traite)
    {
        $totalTranches = max(1, (int) ($traite->nombre_traites ?? 1));
        $emission = $traite->date_emission ? Carbon::parse($traite->date_emission) : null;
        $firstDue = $traite->echeance ? Carbon::parse($traite->echeance) : null;
        $total = (int) round($traite->montant ?? 0);

        // Get organization settings
        $organizationSetting = OrganizationSetting::first();
        $companyName = $organizationSetting ? $organizationSetting->name : 'CFAO MOBILITY CAMEROON';
        $companyLogo = $organizationSetting && $organizationSetting->logo ? url('storage/' . $organizationSetting->logo) : asset('images/LOGO.png');

        $htmlParts = [];
        for ($i = 1; $i <= $totalTranches; $i++) {
            $dueDate = $firstDue ? $firstDue->copy()->addMonthsNoOverflow($i - 1) : null;
            $amountForThisTranche = (int) round($total / max(1, $totalTranches));
            $data = [
                'rangeText' => $i . ' | ' . $totalTranches,
                'ville' => 'Douala', // Ensure ville is always set
                'date_emission' => $emission ? $emission->format('d/m/Y') : '',
                'echeance' => $dueDate ? $dueDate->format('d/m/Y') : '',
                'montant_tranche' => number_format($amountForThisTranche, 0, ',', ' '),
                'montant_tranche_words' => strtoupper($this->numberToFrenchWords($amountForThisTranche)),
                'nom_raison_sociale' => $traite->nom_raison_sociale ?? '',
                'domiciliation' => $traite->domiciliation_bancaire ?? '',
                'rib' => $traite->rib ?? '',
                'numero' => $traite->numero ?? '',
                'date_emission_text_long' => $emission ? $emission->locale('fr')->translatedFormat('d F Y') : '',
                'companyName' => $companyName,
                'companyLogo' => $companyLogo,
            ];
            $htmlParts[] = view('traites.print', $data)->render();
            if ($i < $totalTranches) {
                $htmlParts[] = '<div style="page-break-after: always;"></div>';
            }
        }
        $html = implode("\n", $htmlParts);

        // Utilise Browsershot uniquement (rendu print CSS). Si indisponible, renvoie une erreur explicite.
        if (class_exists(\Spatie\Browsershot\Browsershot::class)) {
            try {
                $previewUrl = route('traites.preview', ['traite' => $traite->id]);
                $binary = Browsershot::url($previewUrl)
                    ->emulateMedia('print')
                    ->showBackground()
                    ->format('A4')
                    ->margins(5, 5, 5, 5)
                    ->windowSize(1024, 1448)
                    ->timeout(120)
                    ->setOption('waitUntil', 'networkidle0')
                    ->setOption('preferCSSPageSize', true)
                    ->pdf();
                return response($binary, 200, [
                    'Content-Type' => 'application/pdf',
                    'Content-Disposition' => 'attachment; filename="traites_'.$traite->id.'.pdf"',
                ]);
            } catch (\Throwable $e) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'La génération PDF de capture requiert Browsershot/Chrome headless.',
                ], 500);
            }
        }

        return response()->json([
            'status' => 'error',
            'message' => 'Browsershot non installé. Installez spatie/browsershot + Chrome/Chromium.',
        ], 500);
    }

    /**
     * Envoie un PDF multi-pages par email en pièce jointe avec objet "Traites"
     */
    public function emailPreview(Request $request, Traite $traite)
    {
        $validated = $request->validate([
            'to' => ['required','email'],
            'subject' => ['nullable','string','max:255'],
            'body' => ['nullable','string','max:5000'],
        ]);

        $totalTranches = max(1, (int) ($traite->nombre_traites ?? 1));
        $emission = $traite->date_emission ? Carbon::parse($traite->date_emission) : null;
        $firstDue = $traite->echeance ? Carbon::parse($traite->echeance) : null;
        $total = (int) round($traite->montant ?? 0);
        $tranches = $this->splitAmountIntoTranches($total, $totalTranches);

        // Construire un HTML à partir de la vue print.blade.php pour chaque tranche
        $htmlParts = [];
        for ($i = 1; $i <= $totalTranches; $i++) {
            $dueDate = $firstDue ? $firstDue->copy()->addMonthsNoOverflow($i - 1) : null;
            $amountForThisTranche = $tranches[$i - 1] ?? 0;
            $amountWords = strtoupper($this->numberToFrenchWords($amountForThisTranche));
            $data = [
                'rangeText' => $i . ' | ' . $totalTranches,
                'ville' => 'Douala', // Ensure ville is always set
                'date_emission' => $emission ? $emission->format('d/m/Y') : '',
                'echeance' => $dueDate ? $dueDate->format('d/m/Y') : '',
                'montant_tranche' => number_format($amountForThisTranche, 0, ',', ' '),
                'montant_tranche_words' => $amountWords,
                'nom_raison_sociale' => $traite->nom_raison_sociale ?? '',
                'domiciliation' => $traite->domiciliation_bancaire ?? '',
                'rib' => $traite->rib ?? '',
                'numero' => $traite->numero ?? '',
                'date_emission_text_long' => $emission ? $emission->locale('fr')->translatedFormat('d F Y') : '',
            ];
            $htmlParts[] = view('traites.print', $data)->render();
            // Ajoute une rupture de page entre les tranches (sauf la dernière)
            if ($i < $totalTranches) {
                $htmlParts[] = '<div style="page-break-after: always;"></div>';
            }
        }
        $html = implode("\n", $htmlParts);

        // Générer une capture PNG via BrowsershotController (obligatoire)
        $pngBinary = null;
        try {
            if (!class_exists(\Spatie\Browsershot\Browsershot::class)) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Browsershot requis: installez spatie/browsershot + Puppeteer/Chromium.'
                ], 500);
            }
            $controller = app(\App\Http\Controllers\BrowsershotController::class);
            $response = $controller->screenshotForTraite($traite);
            if (!($response->status() === 200 && str_contains($response->headers->get('Content-Type', ''), 'image/png'))) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Echec capture PNG via Browsershot.'
                ], 500);
            }
            $pngBinary = $response->getContent();
        } catch (\Throwable $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Echec capture PNG via Browsershot.',
                'error' => $e->getMessage(),
            ], 500);
        }

        $to = $validated['to'];
        $subject = 'Traites';
        $numero = (string)($traite->numero ?? '');
        $body = "Bonjour,\n\nVeuillez trouver ci-joint la traite " . $numero . ".\n\nCordialement.";

        Mail::raw($body, function ($message) use ($to, $subject, $pngBinary, $traite) {
            $message->to($to)
                    ->subject($subject);
            $message->attachData($pngBinary, 'traites_'.$traite->id.'.png', ['mime' => 'image/png']);
        });

        return response()->json(['status' => 'ok']);
    }

    /**
     * Envoie une capture d'image (PNG) de la page d'aperçu multi-pages
     */
    public function emailPreviewImage(Request $request, Traite $traite)
    {
        $validated = $request->validate([
            'to' => ['required','email'],
            'subject' => ['nullable','string','max:255'],
            'body' => ['nullable','string','max:5000'],
        ]);

        $to = $validated['to'];
        $subject = $validated['subject'] ?? 'Traites (image)';
        $numero = (string)($traite->numero ?? '');
        $body = $validated['body'] ?? ("Bonjour,\n\nVeuillez trouver ci-joint l'image de la traite " . $numero . ".\n\nCordialement.");

        $imgBinary = null;
        try {
            if (class_exists(\Spatie\Browsershot\Browsershot::class)) {
                $previewUrl = route('traites.preview', ['traite' => $traite->id]);
                $base64 = Browsershot::url($previewUrl)
                    ->emulateMedia('print') // masque toolbar/footer
                    ->showBackground()
                    ->windowSize(1280, 2000)
                    ->fullPage()
                    ->timeout(120)
                    ->setOption('waitUntil', 'networkidle0')
                    ->base64Screenshot();
                $imgBinary = base64_decode($base64);
            }
        } catch (\Throwable $e) {
            $imgBinary = null;
        }

        if ($imgBinary === null) {
            return response()->json([
                'status' => 'error',
                'message' => "La capture d'image requiert Browsershot/Puppeteer installé."
            ], 500);
        }

        Mail::raw($body, function ($message) use ($to, $subject, $imgBinary, $traite) {
            $message->to($to)
                    ->subject($subject)
                    ->attachData($imgBinary, 'traites_'.$traite->id.'.png', ['mime' => 'image/png']);
        });

        return response()->json(['status' => 'ok']);
    }

    private function numberToFrenchWords(int $number): string
    {
        if ($number === 0) return 'zéro';
        $units = ['', 'un', 'deux', 'trois', 'quatre', 'cinq', 'six', 'sept', 'huit', 'neuf', 'dix', 'onze', 'douze', 'treize', 'quatorze', 'quinze', 'seize'];
        $tens = ['', '', 'vingt', 'trente', 'quarante', 'cinquante', 'soixante'];
        $words = [];

        $appendBelowHundred = function(int $n) use (&$words, $units, $tens, &$appendBelowHundred) {
            if ($n <= 16) { $words[] = $units[$n]; return; }
            if ($n < 20) { $words[] = 'dix-' . $units[$n - 10]; return; }
            if ($n < 70) {
                $t = intdiv($n, 10);
                $u = $n % 10;
                if ($u === 1) $words[] = $tens[$t] . ' et un';
                else if ($u > 0) $words[] = $tens[$t] . '-' . $units[$u];
                else $words[] = $tens[$t];
                return;
            }
            if ($n < 80) { // 70-79: soixante + 10-19
                $rest = $n - 60;
                if ($rest === 11) $words[] = 'soixante et onze';
                else {
                    $words[] = 'soixante';
                    $appendBelowHundred($rest);
                }
                return;
            }
            // 80-99: quatre-vingt(s) + 0-19
            $rest = $n - 80;
            $words[] = 'quatre-vingt' . ($rest === 0 ? 's' : '');
            if ($rest > 0) $appendBelowHundred($rest);
        };

        $appendBelowThousand = function(int $n) use (&$words, $units, &$appendBelowHundred, &$appendBelowThousand) {
            if ($n >= 100) {
                $hundreds = intdiv($n, 100);
                $rest = $n % 100;
                if ($hundreds === 1) {
                    $words[] = 'cent' . ($rest === 0 ? 's' : '');
                } else {
                    $words[] = $units[$hundreds] . ' cent' . ($rest === 0 ? 's' : '');
                }
                if ($rest > 0) $appendBelowHundred($rest);
                return;
            }
            $appendBelowHundred($n);
        };

        $chunks = [1000000000 => 'milliard', 1000000 => 'million', 1000 => 'mille'];
        $n = $number;
        foreach ($chunks as $value => $label) {
            if ($n >= $value) {
                $q = intdiv($n, $value);
                $n %= $value;
                if ($value === 1000 && $q === 1) {
                    $words[] = 'mille';
                } else {
                    $segment = [];
                    $saveRef = &$words; $words = &$segment;
                    $appendBelowThousand($q);
                    $built = trim(preg_replace('/\s+/', ' ', implode(' ', $segment)));
                    $words = &$saveRef;
                    $words[] = $built . ' ' . ($q > 1 ? $label . 's' : $label);
                }
            }
        }
        if ($n > 0) $appendBelowThousand($n);

        return trim(preg_replace('/\s+/', ' ', implode(' ', $words)));
    }

    /**
     * Split a total amount into N tranches with friendly rounding while preserving the sum.
     * Strategy: choose a rounding step based on total magnitude (1,000,000; 1,000; or 1).
     * Then distribute remainder by adding one step to the first K tranches.
     */
    private function splitAmountIntoTranches(int $total, int $n): array
    {
        $n = max(1, $n);
        if ($total <= 0) return array_fill(0, $n, 0);

        // Choose rounding step
        $step = 1;
        if ($total >= 10000000) { // >= 10 millions
            $step = 1000000;      // arrondir au million
        } else if ($total >= 100000) { // >= 100 mille
            $step = 1000;         // arrondir au millier
        }

        // Equal share in steps, floored to step
        $equal = intdiv($total, $n);
        $equalRounded = intdiv($equal, $step) * $step;

        $parts = array_fill(0, $n, $equalRounded);
        $currentSum = $equalRounded * $n;
        $remaining = $total - $currentSum;

        // Convert remaining to steps and distribute to earliest tranches
        $stepsToDistribute = intdiv($remaining + ($step - 1), $step); // ceiling to steps
        for ($i = 0; $i < $n && $stepsToDistribute > 0; $i++) {
            $parts[$i] += $step;
            $stepsToDistribute--;
        }

        // Fix exact total if off due to ceiling
        $diff = array_sum($parts) - $total;
        for ($i = $n - 1; $i >= 0 && $diff > 0; $i--) {
            $reduce = min($diff, $step);
            $parts[$i] -= $reduce;
            $diff -= $reduce;
        }

        return $parts;
    }
    public function store(Request $request)
    {
        $data = $this->validateData($request);

        // Numérotation automatique si non fournie
        if (empty($data['numero'])) {
            $data['numero'] = $this->generateNumero();
        }

        $traite = Traite::create($data);

        // Log activity: Création
        try {
            TraiteActivity::create([
                'traite_id' => $traite->id,
                'user_id' => optional(Auth::user())->id,
                'action' => 'Création',
                'changes' => null,
            ]);
        } catch (\Throwable $e) {
            // ignore logging failures
        }

        return response()->json($traite, 201);
    }

    public function show(Traite $traite)
    {
        return response()->json($traite);
    }

    public function update(Request $request, Traite $traite)
    {
        $data = $this->validateData($request, $traite->id);

        $original = $traite->only(array_keys($data));
        $traite->update($data);
        $updated = $traite->only(array_keys($data));

        // Compute minimal diff
        $changes = [];
        foreach ($updated as $key => $val) {
            $before = $original[$key] ?? null;
            if ($before !== $val) {
                $changes[$key] = ['from' => $before, 'to' => $val];
            }
        }

        if (!empty($changes)) {
            try {
                TraiteActivity::create([
                    'traite_id' => $traite->id,
                    'user_id' => optional(Auth::user())->id,
                    'action' => 'Modification',
                    'changes' => $changes,
                ]);
            } catch (\Throwable $e) {
                // ignore logging failures
            }
        }

        return response()->json($traite);
    }

    public function destroy(Traite $traite)
    {
        $id = $traite->id;
        try {
            TraiteActivity::create([
                'traite_id' => $id,
                'user_id' => optional(Auth::user())->id,
                'action' => 'Suppression',
                'changes' => null,
            ]);
        } catch (\Throwable $e) {
            // ignore logging failures
        }

        $traite->delete();
        return response()->json(['deleted' => true]);
    }

    public function updateStatus(Request $request, Traite $traite)
    {
        $validated = $request->validate([
            'statut' => [
                'required',
                Rule::in(['Non échu', 'Échu', 'Impayé', 'Rejeté', 'Payé'])
            ],
            'date_impaye' => ['nullable', 'date', function ($attribute, $value, $fail) use ($request) {
                if ($request->input('statut') === 'Impayé' && empty($value)) {
                    $fail('La date d\'impayé est obligatoire lorsque le statut est Impayé.');
                }
            }]
        ]);
        
        $updateData = ['statut' => $validated['statut']];
        
        // Si le statut est 'Impayé', enregistrer la date d'impayé
        if ($validated['statut'] === 'Impayé' && isset($validated['date_impaye'])) {
            $updateData['date_impaye'] = $validated['date_impaye'];
        }
        
        $traite->update($updateData);
        return response()->json($traite);
    }

    public function updateDecision(Request $request, Traite $traite)
    {
        $validated = $request->validate([
            'decision' => ['required', 'string', 'max:100']
        ]);
        $traite->update(['decision' => $validated['decision']]);
        return response()->json($traite);
    }

    private function validateData(Request $request, $id = null): array
    {
        $validated = $request->validate([
            'numero' => ['nullable','string','max:10', 'regex:/^(TR-\d{6}-\d{6}|\d{6})$/'],  // Ancien format TR-YYYYMM-###### ou nouveau format 6 chiffres
            'nombre_traites' => ['required','integer','min:1'],
            'echeance' => ['required','date'],
            'date_emission' => ['required','date'],
            'montant' => ['required','numeric','min:0'],
            'nom_raison_sociale' => ['required','string','max:255'],
            'domiciliation_bancaire' => ['nullable','string','max:255'],
            'rib' => ['nullable','string','max:50', 'regex:/^[0-9\s-]+$/'],
            'motif' => ['nullable','string','max:500'],
            'origine_traite' => ['nullable','string','max:100'],
            'commentaires' => ['nullable','string','max:1000'],
            'statut' => ['nullable', Rule::in(['Non échu', 'Échu', 'Impayé', 'Rejeté', 'Payé'])],
            'decision' => ['nullable', 'string', 'max:100'],
            'date_impaye' => ['nullable', 'date'],
        ]);
        
        // S'assurer que statut n'est jamais null (utiliser la valeur par défaut)
        if (is_null($validated['statut'])) {
            $validated['statut'] = 'Non échu';
        }
        
        return $validated;
    }

    private function generateNumero(): string
    {
        // Nouveau système: séquence à 6 chiffres commençant à 100000
        // Trouver le numéro maximum existant dans la base
        $lastNumero = Traite::where('numero', '>=', '100000')
                         ->where('numero', '<=', '999999')
                         ->whereRaw('numero REGEXP "^[0-9]{6}$"')
                         ->max('numero');
        
        if ($lastNumero && is_numeric($lastNumero) && $lastNumero >= 100000) {
            $nextNumero = (int)$lastNumero + 1;
        } else {
            // Si aucun numéro dans le nouveau format n'existe encore, commencer à 100000
            $nextNumero = 100000;
        }
        
        return (string)$nextNumero;
    }

    /**
     * Convertit une date du format DD/MM/YYYY vers YYYY-MM-DD
     */
    private function convertDateFormat($dateString): string
    {
        if (empty($dateString)) {
            return date('Y-m-d');
        }

        // Si c'est déjà au format YYYY-MM-DD, on le retourne tel quel
        if (preg_match('/^\d{4}-\d{2}-\d{2}/', $dateString)) {
            return substr($dateString, 0, 10); // Garde seulement la partie date
        }

        // Si c'est au format DD/MM/YYYY ou DD/MM/YYYY HH:MM
        if (preg_match('/^(\d{1,2})\/(\d{1,2})\/(\d{4})/', $dateString, $matches)) {
            $day = str_pad($matches[1], 2, '0', STR_PAD_LEFT);
            $month = str_pad($matches[2], 2, '0', STR_PAD_LEFT);
            $year = $matches[3];
            return "$year-$month-$day";
        }

        // Si aucun format reconnu, retourner la date actuelle
        return date('Y-m-d');
    }

    /**
     * Calcule la différence en jours entre deux dates
     */
    private function calculateDateDifference($date1, $date2): int
    {
        $d1 = new \DateTime($date1);
        $d2 = new \DateTime($date2);
        return abs($d1->diff($d2)->days);
    }

    /**
     * Vérifie les doublons par nombre de traites ET montant dans les données CSV avant importation
     * Garde la traite dont l'échéance est la plus proche de la date d'émission
     * Si le montant est différent, les deux traites sont conservées
     */
    private function checkCsvDuplicates($data): array
    {
        $duplicates = [];
        $seenTraites = []; // Stocke nbTraites + montant + nom comme clé
        
        foreach ($data as $index => $item) {
            $nbTraites = (int)($item['nombre_traites'] ?? 0);
            $montant = (float)($item['montant'] ?? 0);
            $nom = $item['nom_raison_sociale'] ?? '';
            
            // Vérifier les doublons par nombre de traites + montant + nom
            if ($nbTraites > 0 && $montant > 0 && $nom) {
                $cleTraite = $nbTraites . '_' . $montant . '_' . md5($nom); // Clé composite avec nom
                
                if (isset($seenTraites[$cleTraite])) {
                    // Comparer les dates pour garder la meilleure traite
                    $currentEcheance = $this->convertDateFormat($item['echeance'] ?? '');
                    $currentDateEmission = $this->convertDateFormat($item['date_emission'] ?? '');
                    $currentDiff = $this->calculateDateDifference($currentEcheance, $currentDateEmission);
                    
                    $existingIndex = $seenTraites[$cleTraite] - 1; // Convertir en index 0-based
                    $existingEcheance = $this->convertDateFormat($data[$existingIndex]['echeance'] ?? '');
                    $existingDateEmission = $this->convertDateFormat($data[$existingIndex]['date_emission'] ?? '');
                    $existingDiff = $this->calculateDateDifference($existingEcheance, $existingDateEmission);
                    
                    if ($currentDiff < $existingDiff) {
                        // La traite actuelle est meilleure, marquer l'ancienne comme doublon
                        $duplicates[] = [
                            'line' => $seenTraites[$cleTraite],
                            'numero' => $data[$existingIndex]['numero'] ?? '',
                            'reason' => "Doublon pour client '{$nom}', nombre de traites ({$nbTraites}) et montant ({$montant}) - remplacée par une traite avec échéance plus proche de la date d'émission"
                        ];
                        $seenTraites[$cleTraite] = $index + 1; // Remplacer par la nouvelle ligne
                    } else {
                        // L'ancienne traite est meilleure, marquer la actuelle comme doublon
                        $duplicates[] = [
                            'line' => $index + 1,
                            'numero' => $item['numero'] ?? '',
                            'reason' => "Doublon pour client '{$nom}', nombre de traites ({$nbTraites}) et montant ({$montant}) - échéance moins proche de la date d'émission"
                        ];
                    }
                } else {
                    $seenTraites[$cleTraite] = $index + 1;
                }
            }
        }
        
        return $duplicates;
    }

    /**
     * Aperçu de l'acceptation d'une traite
     */
    public function acceptancePreview(Traite $traite)
    {
        // Get organization settings
        $organizationSetting = OrganizationSetting::first();
        $companyName = $organizationSetting ? $organizationSetting->name : 'CFAO MOBILITY CAMEROON';
        
        // Get request parameters
        $decision = request('decision', 'Encaissement');
        $branchDepartment = request('branch_dept', request('branche_code', ''));
        $creditAccount = request('credit_account', request('credit', '4111'));
        $agosType = request('agos_type', request('agios', 'Tiré'));
        
        // Format dates
        $emission = $traite->date_emission ? Carbon::parse($traite->date_emission) : null;
        $echeance = $traite->echeance ? Carbon::parse($traite->echeance) : null;
        
        // Format amounts
        $total = (int) round($traite->montant ?? 0);
        $montantFormatted = number_format($total, 0, ',', ' ');
        
        // Handle multiple traites (tranches)
        $nombreTraites = max(1, (int) ($traite->nombre_traites ?? 1));
        $traites = [];
        $totalGeneral = 0;
        
        // Split the total amount into tranches
        $montantParTranche = (int) round($total / $nombreTraites);
        
        for ($i = 0; $i < $nombreTraites; $i++) {
            // Calculate due date for each tranche
            $dueDate = $echeance ? $echeance->copy()->addMonthsNoOverflow($i) : null;
            
            $traites[] = [
                'numero_ordre' => str_pad($i + 1, 2, '0', STR_PAD_LEFT),
                'numero' => $traite->numero ?? '',
                'echeance' => $dueDate ? $dueDate->format('d/m/Y') : '',
                'montant' => $montantParTranche,
                'montant_formatted' => number_format($montantParTranche, 0, ',', ' ')
            ];
            
            $totalGeneral += $montantParTranche;
        }
        
        // Format total general
        $totalGeneralFormatted = number_format($totalGeneral, 0, ',', ' ');
        
        // Current date for document
        $currentDate = Carbon::now();
        
        // Data for the view
        $data = [
            'ville' => 'Douala',
            'current_date_long' => $currentDate->locale('fr')->translatedFormat('d F Y'),
            'current_date' => $currentDate->format('d/m/Y'),
            'montant_formatted' => $montantFormatted,
            'domiciliation' => $traite->domiciliation_bancaire ?? '',
            'rib' => $traite->rib ?? '',
            'numero' => $traite->numero ?? '',
            'echeance' => $echeance ? $echeance->format('d/m/Y') : '',
            'nom_raison_sociale' => $traite->nom_raison_sociale ?? '',
            'companyName' => $companyName,
            'decision' => $decision,
            'branch_department' => $branchDepartment,
            'credit_account' => $creditAccount,
            'agos_type' => $agosType,
            'traites' => $traites,
            'total_general_formatted' => $totalGeneralFormatted,
            'nombre_traites' => $nombreTraites
        ];
        
        return response()->view('traites.acceptance', $data);
    }

    /**
     * Historique des traites - Affiche uniquement la dernière activité pour l'affichage dans l'interface.
     */
    public function historique(Request $request)
    {
        $type = $request->get('type'); // 'client' or 'mois'
        $nom = $request->get('nom_raison_sociale');
        $month = $request->get('month'); // YYYY-MM

        // Objectif: retourner TOUTES les traites, avec la dernière action et l'utilisateur s'ils existent
        $query = Traite::query()
            ->with(['latestActivity.user:id,username'])
            ->select(['id','numero','nom_raison_sociale','montant','statut','echeance','date_emission','created_at']);

        if ($type === 'client' && $nom) {
            $query->where('nom_raison_sociale', 'like', "%$nom%");
        }

        if ($type === 'mois' && $month && preg_match('/^\\d{4}-\\d{2}$/', $month)) {
            // Filtrer par mois sur la date d'émission (ou created_at si vous préférez)
            $parts = explode('-', $month);
            $yyyy = (int)($parts[0] ?? date('Y'));
            $mm = (int)($parts[1] ?? date('m'));
            $lastDay = cal_days_in_month(CAL_GREGORIAN, $mm, $yyyy);
            $start = sprintf('%04d-%02d-01', $yyyy, $mm);
            $end = sprintf('%04d-%02d-%02d', $yyyy, $mm, $lastDay);
            $query->whereBetween('date_emission', [$start, $end]);
        }

        $traites = $query->orderByDesc('date_emission')->get();

        $mapped = $traites->map(function($t) {
            // Récupérer la dernière activité et l'utilisateur associé
            $act = $t->latestActivity; // peut être null
            $action = $act?->action ?? 'Création';
            $user = $act?->user; // peut être null
            $displayUser = $user?->username ?? $user?->name ?? null;
            $changes = $act?->changes; // Ajouter les détails des modifications
            // Choisir une date sûre: priorité à la date de l'activité, sinon date_emission, sinon echeance, sinon created_at de la traite
            $date = $act && $act->created_at ? $act->created_at->toDateTimeString() : (
                ($t->date_emission ?: ($t->echeance ?: ($t->created_at ?? '')))
            );
            return [
                'date' => (string)$date,
                'nom_raison_sociale' => $t->nom_raison_sociale,
                'numero_traite' => $t->numero,
                'montant' => $t->montant,
                'action' => $action,
                'statut' => $t->statut,
                'username' => $displayUser,
                'changes' => $changes, // Inclure les détails des modifications
            ];
        })
        // trier par la date calculée décroissante (plus récent en premier)
        ->sortByDesc(function($row) {
            return $row['date'] ?? '';
        })
        ->values();

        return response()->json($mapped);
    }

    /**
     * Export des historiques traites - Retourne toutes les activités pour l'exportation avec le contenu complet de la grille.
     */
    public function exportHistorique(Request $request)
    {
        $type = $request->get('type'); // 'client' or 'mois'
        $nom = $request->get('nom_raison_sociale');
        $month = $request->get('month'); // YYYY-MM

        // Objectif: retourner TOUTES les traites, avec toutes les activités et les utilisateurs associés pour l'exportation
        $query = Traite::query()
            ->with(['activities.user:id,username'])
            ->select(['id','numero','nom_raison_sociale','montant','statut','echeance','date_emission','created_at']);

        if ($type === 'client' && $nom) {
            $query->where('nom_raison_sociale', 'like', "%$nom%");
        }

        if ($type === 'mois' && $month && preg_match('/^\\d{4}-\\d{2}$/', $month)) {
            // Filtrer par mois sur la date d'émission (ou created_at si vous préférez)
            $parts = explode('-', $month);
            $yyyy = (int)($parts[0] ?? date('Y'));
            $mm = (int)($parts[1] ?? date('m'));
            $lastDay = cal_days_in_month(CAL_GREGORIAN, $mm, $yyyy);
            $start = sprintf('%04d-%02d-01', $yyyy, $mm);
            $end = sprintf('%04d-%02d-%02d', $yyyy, $mm, $lastDay);
            $query->whereBetween('date_emission', [$start, $end]);
        }

        $traites = $query->orderByDesc('date_emission')->get();

        // Collecter toutes les activités de toutes les traites avec leurs informations complètes
        $allActivities = collect();
        
        foreach ($traites as $traite) {
            // Regrouper les activités par date et utilisateur pour éviter les duplications
            $activitiesByDate = [];
            
            foreach ($traite->activities as $activity) {
                $dateKey = $activity->created_at ? $activity->created_at->toDateTimeString() : ($traite->created_at ? $traite->created_at->toDateTimeString() : now()->toDateTimeString());
                
                // Créer une clé unique basée sur la date et la traite
                $uniqueKey = $dateKey . '_' . $traite->id;
                
                if (!isset($activitiesByDate[$uniqueKey])) {
                    $activitiesByDate[$uniqueKey] = [
                        'date' => $dateKey,
                        'nom_raison_sociale' => $traite->nom_raison_sociale,
                        'numero_traite' => $traite->numero,
                        'montant' => $traite->montant,
                        'action' => $activity->action,
                        'statut' => $traite->statut,
                        'username' => $activity->user?->username ?? $activity->user?->name ?? null,
                        'changes' => [],
                    ];
                }
                
                // Fusionner les changements s'il y a plusieurs activités à la même date
                if ($activity->changes) {
                    foreach ($activity->changes as $field => $change) {
                        if (!isset($activitiesByDate[$uniqueKey]['changes'][$field])) {
                            $activitiesByDate[$uniqueKey]['changes'][$field] = $change;
                        }
                    }
                }
            }
            
            // Si la traite n'a pas d'activités, ajouter une entrée pour la création
            if ($traite->activities->isEmpty()) {
                $dateKey = $traite->created_at ? $traite->created_at->toDateTimeString() : now()->toDateTimeString();
                $uniqueKey = $dateKey . '_' . $traite->id;
                
                $activitiesByDate[$uniqueKey] = [
                    'date' => $dateKey,
                    'nom_raison_sociale' => $traite->nom_raison_sociale,
                    'numero_traite' => $traite->numero,
                    'montant' => $traite->montant,
                    'action' => 'Création',
                    'statut' => $traite->statut,
                    'username' => null,
                    'changes' => null,
                ];
            }
            
            // Ajouter les activités regroupées à la collection principale
            foreach ($activitiesByDate as $activity) {
                // Convertir le tableau de changements en objet si nécessaire
                if (!empty($activity['changes'])) {
                    $activity['changes'] = (object)$activity['changes'];
                }
                
                $allActivities->push($activity);
            }
        }

        // Trier TOUTES les données par date décroissante (plus récent en premier)
        // Tous types d'actions confondus (création et modification)
        $sortedActivities = $allActivities->sortByDesc(function($row) {
            return $row['date'] ?? '';
        })->values();

        return response()->json($sortedActivities);
    }

    /**
     * Export complet des traites - Retourne toutes les traites avec tous les détails.
     */
    public function exportWithDetails(Request $request): \Illuminate\Http\JsonResponse
    {
        try {
            \Log::info('ExportWithDetails called with params:', $request->all());
            $query = DB::table('traites')
            ->select([
                'traites.id',
                'traites.numero',
                'traites.nombre_traites',
                'traites.echeance',
                'traites.date_emission',
                'traites.montant',
                'traites.nom_raison_sociale',
                'traites.domiciliation_bancaire',
                'traites.rib',
                'traites.motif',
                'traites.commentaires',
                'traites.statut',
                'traites.decision',
                'traites.origine_traite',
                'traites.date_impaye'
            ]);

        // Recherche
        if ($search = trim((string) $request->get('search', ''))) {
            $query->where(function ($q) use ($search) {
                $q->where('traites.numero', 'LIKE', "%{$search}%")
                  ->orWhere('traites.nom_raison_sociale', 'LIKE', "%{$search}%")
                  ->orWhere('traites.statut', 'LIKE', "%{$search}%")
                  ->orWhere('traites.origine_traite', 'LIKE', "%{$search}%");
            });
        }

        // Filtre par statut
        if ($statut = $request->get('statut')) {
            $query->where('traites.statut', $statut);
        }

        // Filtre par origine_traite
        if ($origine_traite = $request->get('origine_traite')) {
            $query->where('traites.origine_traite', $origine_traite);
        }

        // Filtre par date
        if ($from = $request->get('from')) {
            $query->where('traites.echeance', '>=', $from);
        }
        if ($to = $request->get('to')) {
            $query->where('traites.echeance', '<=', $to);
        }

        // Tri
        $sortRequest = (string) $request->get('sort', 'echeance');
        $direction = strtolower((string) $request->get('dir', 'asc')) === 'desc' ? 'desc' : 'asc';

        $allowedSorts = [
            'numero' => 'traites.numero',
            'echeance' => 'traites.echeance',
            'date_emission' => 'traites.date_emission',
            'montant' => 'traites.montant',
            'nom_raison_sociale' => 'traites.nom_raison_sociale',
            'statut' => 'traites.statut',
            'origine_traite' => 'traites.origine_traite',
            'created_at' => 'traites.created_at',
        ];

        if (!array_key_exists($sortRequest, $allowedSorts)) {
            $sortRequest = 'echeance';
        }
        
        \Log::info('About to apply orderBy with sortRequest: ' . $sortRequest . ' and direction: ' . $direction);
        \Log::info('Value from allowedSorts: ' . ($allowedSorts[$sortRequest] ?? 'KEY_NOT_FOUND'));
        
        if (!isset($allowedSorts[$sortRequest])) {
            \Log::error('Sort request key not found in allowedSorts: ' . $sortRequest);
            throw new \Exception('Invalid sort parameter');
        }
        
        $query->orderBy($allowedSorts[$sortRequest], $direction);

        // Limiter le nombre de résultats pour l'export
        $perPage = max(1, min((int) $request->get('per_page', 1000), 10000));
        \Log::info('Query prepared, about to paginate with perPage: ' . $perPage);
        \Log::info('Query SQL: ' . $query->toSql());
        \Log::info('Query bindings: ', $query->getBindings());
        
        try {
            $results = $query->paginate($perPage);
            \Log::info('Pagination successful, total results: ' . $results->total());
        } catch (\Exception $e) {
            \Log::error('Error in exportWithDetails pagination: ' . $e->getMessage());
            throw $e;
        }

        return response()->json([
            'data' => $results->items(),
            'current_page' => $results->currentPage(),
            'last_page' => $results->lastPage(),
            'per_page' => $results->perPage(),
            'total' => $results->total(),
        ], 200, [], JSON_UNESCAPED_UNICODE);
        } catch (\Exception $e) {
            \Log::error('Error in exportWithDetails: ' . $e->getMessage(), [
                'error' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString()
            ]);
            return response()->json([
                'error' => 'Erreur lors de l\'exportation',
                'message' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * Import CSV avec validation des doublons
     */
    public function importCsv(Request $request)
    {
        try {
            \Log::info('=== DÉBUT IMPORT CSV ===');
            \Log::info('Request data: ' . json_encode($request->all()));
            
            // Augmenter les limites pour les gros imports
            ini_set('memory_limit', '512M');
            ini_set('max_execution_time', 300);
            
            // Récupérer les données avec le mapping déjà fait par le frontend
            $data = $request->input('data', []);
            $duplicateAction = $request->input('duplicate_action', 'skip');
            
            \Log::info('Data count: ' . count($data));
            \Log::info('Duplicate action: ' . $duplicateAction);
            
            // Vérifier la taille des données
            $dataSize = strlen(json_encode($data));
            \Log::info('Data size: ' . $dataSize . ' bytes (' . round($dataSize / 1024 / 1024, 2) . ' MB)');
            
            // Étape supplémentaire : pré-filtrage CSV, conservation d'une seule par 
            // (nom, montant, nombre_traites, date_emission) : on conserve la meilleure (écart le plus faible) pour chaque groupe
            $filtered = [];
            foreach ($data as $row) {
                $nom = trim($row['nom_raison_sociale'] ?? '');
                $nbTraites = (int)($row['nombre_traites'] ?? 0);
                $montant = (float)($row['montant'] ?? 0);
                $dateEmission = isset($row['date_emission']) ? $this->convertDateFormat($row['date_emission']) : null;
                $echeance = isset($row['echeance']) ? $this->convertDateFormat($row['echeance']) : null;
                // La clé NE comprend plus l'échéance
                if (!$nom || !$nbTraites || !$montant || !$dateEmission || !$echeance) continue;
                $key = md5($nom).'_'.$montant.'_'.$nbTraites.'_'.$dateEmission;
                $diff = $this->calculateDateDifference($echeance, $dateEmission);
                if (!isset($filtered[$key]) || $diff < $filtered[$key]['_diff']) {
                    $row['_diff'] = $diff;
                    $filtered[$key] = $row;
                }
            }
            $data = array_map(function($row) {
                unset($row['_diff']);
                return $row;
            }, array_values($filtered));
            
            // Vérifier les doublons dans le fichier CSV lui-même
            $csvDuplicates = $this->checkCsvDuplicates($data);
            if (!empty($csvDuplicates)) {
                \Log::warning('Doublons détectés dans le fichier CSV: ' . count($csvDuplicates));
            }
            
            $imported = 0;
            $skipped = 0;
            $errors = [];
            $duplicates = $csvDuplicates;
            
            // Traitement par lots pour les gros imports
            $batchSize = 1000; // Traiter par lots de 1000 éléments
            $totalItems = count($data);
            \Log::info("Traitement de {$totalItems} éléments par lots de {$batchSize}");
            
            for ($batchStart = 0; $batchStart < $totalItems; $batchStart += $batchSize) {
                $batchEnd = min($batchStart + $batchSize, $totalItems);
                $batch = array_slice($data, $batchStart, $batchSize);
                
                \Log::info("Traitement du lot " . ($batchStart / $batchSize + 1) . " (éléments {$batchStart}-{$batchEnd})");
                
                foreach ($batch as $index => $item) {
                    $actualIndex = $batchStart + $index;
                    \Log::info("Traitement ligne " . ($actualIndex + 1) . ": " . json_encode($item));
                
                    try {
                    // Vérifier les doublons par nombre de traites + montant + nom
                    $numero = $item['numero'] ?? '';
                    $nbTraites = (int)($item['nombre_traites'] ?? 0);
                    $montant = (float)($item['montant'] ?? 0);
                    $nom = $item['nom_raison_sociale'] ?? '';
                    $existingTraite = null;
                    
                    // Vérifier si le nombre de traites, le montant ET le nom existent déjà en base
                    if ($nbTraites > 0 && $montant > 0 && $nom) {
                        $existingTraite = Traite::where('nombre_traites', $nbTraites)
                                               ->where('montant', $montant)
                                               ->where('nom_raison_sociale', $nom)
                                               ->first();
                        if ($existingTraite) {
                            // Comparer les dates pour décider si remplacer
                            $currentEcheance = $this->convertDateFormat($item['echeance'] ?? '');
                            $currentDateEmission = $this->convertDateFormat($item['date_emission'] ?? '');
                            $currentDiff = $this->calculateDateDifference($currentEcheance, $currentDateEmission);
                            
                            $existingDiff = $this->calculateDateDifference($existingTraite->echeance, $existingTraite->date_emission);
                            
                            if ($currentDiff < $existingDiff) {
                                // La traite actuelle est meilleure, remplacer
                                \Log::info("Doublon détecté ligne " . ($actualIndex + 1) . ": Client '{$nom}', nombre de traites {$nbTraites} et montant {$montant} - remplacement par traite avec échéance plus proche");
                                $existingTraite->delete();
                                \Log::info("Ancienne traite supprimée: client '{$nom}', nombre de traites {$nbTraites} et montant {$montant} (échéance moins proche)");
                            } else {
                                // L'ancienne traite est meilleure, ignorer la nouvelle
                                \Log::info("Doublon détecté ligne " . ($actualIndex + 1) . ": Client '{$nom}', nombre de traites {$nbTraites} et montant {$montant} - échéance moins proche que celle en base");
                                $duplicates[] = [
                                    'line' => $existingTraite->id,
                                    'numero' => $numero,
                                    'reason' => "Client '{$nom}', nombre de traites ({$nbTraites}) et montant ({$montant}) déjà existant en base (échéance moins proche de la date d'émission)"
                                ];
                                
                                if ($duplicateAction === 'skip') {
                                    $skipped++;
                                    \Log::info("Ligne " . ($actualIndex + 1) . " ignorée (doublon en base)");
                                    continue;
                                }
                            }
                        }
                    }
                    
                    // Vérifier aussi si cette ligne est un doublon CSV
                    $isCsvDuplicate = false;
                    foreach ($csvDuplicates as $csvDup) {
                        if ($csvDup['line'] === ($actualIndex + 1)) {
                            $isCsvDuplicate = true;
                            break;
                        }
                    }
                    
                    if ($isCsvDuplicate && $duplicateAction === 'skip') {
                        $skipped++;
                        \Log::info("Ligne " . ($actualIndex + 1) . " ignorée (doublon CSV)");
                        continue;
                    }
                    
                    // Les données sont déjà mappées par le frontend, on les utilise directement
                    // Convertir les dates du format DD/MM/YYYY vers YYYY-MM-DD
                    $echeance = $this->convertDateFormat($item['echeance'] ?? date('Y-m-d'));
                    $dateEmission = $this->convertDateFormat($item['date_emission'] ?? date('Y-m-d'));
                    
                    // Calcul du statut automatique :
                    if ($echeance < date('Y-m-d')) {
                        $statut = 'Échu';
                    } else {
                        $statut = 'Non échu';
                    }

                    $traiteData = [
                        'numero' => $numero ?: $this->generateNumero(),
                        'nombre_traites' => (int)($item['nombre_traites'] ?? 1),
                        'echeance' => $echeance,
                        'date_emission' => $dateEmission,
                        'montant' => (float)($item['montant'] ?? 0),
                        'nom_raison_sociale' => $item['nom_raison_sociale'] ?? 'Client sans nom (Import CSV)',
                        'domiciliation_bancaire' => $item['domiciliation_bancaire'] ?? '',
                        'rib' => $item['rib'] ?? '',
                        'motif' => $item['motif'] ?? '',
                        'origine_traite' => $item['origine_traite'] ?? '',
                        'commentaires' => $item['commentaires'] ?? '',
                        'statut' => $statut, // toujours prendre le statut calculé
                        'date_impaye' => isset($item['date_impaye']) ? $this->convertDateFormat($item['date_impaye']) : null,
                    ];
                    
                    \Log::info("Données traite ligne " . ($actualIndex + 1) . ": " . json_encode($traiteData));

                    $traite = Traite::create($traiteData);
                    \Log::info("Traite créée pour ligne " . ($actualIndex + 1) . ": ID {$traite->id}");

                    // Créer une activité pour l'import CSV
                    try {
                        TraiteActivity::create([
                            'traite_id' => $traite->id,
                            'user_id' => optional(Auth::user())->id,
                            'action' => 'Création',
                            'changes' => null,
                        ]);
                    } catch (\Throwable $e) {
                        \Log::warning("Impossible de créer l'activité pour la traite {$traite->id}: " . $e->getMessage());
                    }

                    $imported++;
                    
                    } catch (\Throwable $e) {
                        \Log::error("Erreur ligne " . ($actualIndex + 1) . ": " . $e->getMessage());
                        $errors[] = "Ligne " . ($actualIndex + 1) . ": " . $e->getMessage();
                    }
                }
                
                // Libérer la mémoire après chaque lot
                if (function_exists('gc_collect_cycles')) {
                    gc_collect_cycles();
                }
                \Log::info("Lot " . ($batchStart / $batchSize + 1) . " terminé. Mémoire utilisée: " . round(memory_get_usage() / 1024 / 1024, 2) . " MB");
            }

            $result = [
                'imported' => $imported,
                'skipped' => $skipped,
                'errors' => $errors,
                'duplicates' => $duplicates,
                'message' => "Import terminé: {$imported} traites importées, {$skipped} doublons ignorés"
            ];
            
            \Log::info('=== FIN IMPORT CSV === ' . json_encode($result));
            
            return response()->json($result)
                ->header('Access-Control-Allow-Origin', 'http://localhost:3000')
                ->header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
                ->header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
                ->header('Access-Control-Allow-Credentials', 'true');
                
        } catch (\Throwable $e) {
            \Log::error('Erreur globale import CSV: ' . $e->getMessage());
            \Log::error('Stack trace: ' . $e->getTraceAsString());
            
            return response()->json([
                'error' => true,
                'message' => 'Erreur lors de l\'importation: ' . $e->getMessage()
            ], 500)
                ->header('Access-Control-Allow-Origin', 'http://localhost:3000')
                ->header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
                ->header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
                ->header('Access-Control-Allow-Credentials', 'true');
        }
    }
}