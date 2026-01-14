<?php

namespace App\Http\Controllers;

use App\Models\Traite;
use Illuminate\Http\Response;
use Spatie\Browsershot\Browsershot;
use Barryvdh\DomPDF\Facade\Pdf;
use Illuminate\Support\Carbon;

class BrowsershotController extends Controller
{
    /**
     * Test simple: capture PNG d'une page publique pour valider l'environnement.
     */
    public function test(): Response
    {
        $pngPath = storage_path('app/public/browsershot-test.png');

        $dir = dirname($pngPath);
        if (! is_dir($dir)) {
            mkdir($dir, 0775, true);
        }

        $nodeBinary = env('NODE_BINARY', 'C:\\Program Files\\nodejs\\node.exe');
        $npmBinary = env('NPM_BINARY', 'C:\\Program Files\\nodejs\\npm.cmd');
        $chromiumPath = env('CHROMIUM_PATH');

        try {
            $shot = Browsershot::url('https://example.com')
                ->windowSize(1280, 1000)
                ->deviceScaleFactor(2)
                ->timeout(120)
                ->setDelay(300)
                ->setOption('waitUntil', 'networkidle0')
                ->setNodeBinary($nodeBinary)
                ->setNpmBinary($npmBinary)
                ->setOption('args', ['--no-sandbox', '--disable-setuid-sandbox'])
                ->userAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36');
            if (! empty($chromiumPath)) {
                $shot->setChromiumPath($chromiumPath);
            }
            $shot->save($pngPath);

            $contents = file_get_contents($pngPath);
            return new Response($contents, 200, [
                'Content-Type' => 'image/png',
                'Content-Disposition' => 'inline; filename="browsershot-test.png"',
            ]);
        } catch (\Throwable $e) {
            return new Response(json_encode([
                'status' => 'error',
                'message' => 'Echec Browsershot',
                'error' => $e->getMessage(),
            ], JSON_PRETTY_PRINT), 500, [
                'Content-Type' => 'application/json; charset=utf-8',
            ]);
        }
    }

    /**
     * Génère un PDF (binaire) fidèle au CSS de la blade print en rendant le HTML directement.
     */
    public function pdfForTraite(Traite $traite): Response
    {
        $nodeBinary = env('NODE_BINARY', 'C:\\Program Files\\nodejs\\node.exe');
        $npmBinary = env('NPM_BINARY', 'C:\\Program Files\\nodejs\\npm.cmd');
        $chromiumPath = env('CHROMIUM_PATH');

        try {
            // Construit le HTML multi-pages directement depuis la blade print
            $totalTranches = max(1, (int) ($traite->nombre_traites ?? 1));
            $emission = $traite->date_emission ? Carbon::parse($traite->date_emission) : null;
            $firstDue = $traite->echeance ? Carbon::parse($traite->echeance) : null;

            $total = (int) round($traite->montant ?? 0);
            $tranches = $this->splitAmountIntoTranches($total, $totalTranches);

            $htmlParts = [];
            for ($i = 1; $i <= $totalTranches; $i++) {
                $dueDate = $firstDue ? $firstDue->copy()->addMonthsNoOverflow($i - 1) : null;
                $amountForThisTranche = $tranches[$i - 1] ?? 0;
                $data = [
                    'rangeText' => $i . ' | ' . $totalTranches,
                    'ville' => 'Douala',
                    'date_emission' => $emission ? $emission->format('d/m/Y') : '',
                    'echeance' => $dueDate ? $dueDate->format('d/m/Y') : '',
                    'montant_tranche' => number_format($amountForThisTranche, 0, ',', ' '),
                    'montant_tranche_words' => strtoupper($this->numberToFrenchWords($amountForThisTranche)),
                    'nom_raison_sociale' => $traite->nom_raison_sociale ?? '',
                    'domiciliation' => $traite->domiciliation_bancaire ?? '',
                    'rib' => $traite->rib ?? '',
                    'numero' => $traite->numero ?? '',
                    'date_emission_text_long' => $emission ? $emission->locale('fr')->translatedFormat('d F Y') : '',
                ];
                $htmlParts[] = view('traites.print', $data)->render();
                if ($i < $totalTranches) {
                    $htmlParts[] = '<div style="page-break-after: always;"></div>';
                }
            }
            $html = implode("\n", $htmlParts);

            $shot = Browsershot::html($html)
                ->emulateMedia('screen')
                ->showBackground()
                ->format('A4')
                ->margins(0, 0, 0, 0) // Suppression des marges pour remplir toute la page
                ->windowSize(1920, 2715) // Taille plus grande pour une meilleure qualité
                ->deviceScaleFactor(3) // Qualité plus élevée
                ->timeout(180)
                ->setDelay(500)
                ->setOption('waitUntil', 'networkidle0')
                ->setOption('preferCSSPageSize', true)
                ->setOption('landscape', false)
                ->setNodeBinary($nodeBinary)
                ->setNpmBinary($npmBinary)
                ->setOption('args', ['--no-sandbox', '--disable-setuid-sandbox', '--disable-web-security'])
                ->userAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36');
            if (! empty($chromiumPath)) {
                $shot->setChromiumPath($chromiumPath);
            }
            $pdfBinary = $shot->pdf();
            return new Response($pdfBinary, 200, [
                'Content-Type' => 'application/pdf',
                'Content-Disposition' => 'inline; filename="traites_'.$traite->id.'.pdf"',
            ]);
        } catch (\Throwable $e) {
            return new Response(json_encode([
                'status' => 'error',
                'message' => 'Echec génération PDF via Browsershot',
                'error' => $e->getMessage(),
            ], JSON_PRETTY_PRINT), 500, [
                'Content-Type' => 'application/json; charset=utf-8',
            ]);
        }
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
            if ($n < 80) { $rest = $n - 60; if ($rest === 11) $words[] = 'soixante et onze'; else { $words[] = 'soixante'; $appendBelowHundred($rest); } return; }
            $rest = $n - 80; $words[] = 'quatre-vingt' . ($rest === 0 ? 's' : ''); if ($rest > 0) $appendBelowHundred($rest);
        };

        $appendBelowThousand = function(int $n) use (&$words, $units, &$appendBelowHundred, &$appendBelowThousand) {
            if ($n >= 100) {
                $hundreds = intdiv($n, 100); $rest = $n % 100;
                if ($hundreds === 1) { $words[] = 'cent' . ($rest === 0 ? 's' : ''); }
                else { $words[] = $units[$hundreds] . ' cent' . ($rest === 0 ? 's' : ''); }
                if ($rest > 0) $appendBelowHundred($rest); return;
            }
            $appendBelowHundred($n);
        };

        $chunks = [1000000000 => 'milliard', 1000000 => 'million', 1000 => 'mille'];
        $n = $number;
        foreach ($chunks as $value => $label) {
            if ($n >= $value) {
                $q = intdiv($n, $value); $n %= $value;
                if ($value === 1000 && $q === 1) { $words[] = 'mille'; }
                else { $segment = []; $saveRef = &$words; $words = &$segment; $appendBelowThousand($q); $built = trim(preg_replace('/\s+/', ' ', implode(' ', $segment))); $words = &$saveRef; $words[] = $built . ' ' . ($q > 1 ? $label . 's' : $label); }
            }
        }
        if ($n > 0) $appendBelowThousand($n);
        return trim(preg_replace('/\s+/', ' ', implode(' ', $words)));
    }

    private function splitAmountIntoTranches(int $total, int $n): array
    {
        $n = max(1, $n);
        if ($total <= 0) return array_fill(0, $n, 0);
        $step = 1; if ($total >= 10000000) { $step = 1000000; } else if ($total >= 100000) { $step = 1000; }
        $equal = intdiv($total, $n); $equalRounded = intdiv($equal, $step) * $step;
        $parts = array_fill(0, $n, $equalRounded); $currentSum = $equalRounded * $n; $remaining = $total - $currentSum;
        $stepsToDistribute = intdiv($remaining + ($step - 1), $step);
        for ($i = 0; $i < $n && $stepsToDistribute > 0; $i++) { $parts[$i] += $step; $stepsToDistribute--; }
        $diff = array_sum($parts) - $total;
        for ($i = $n - 1; $i >= 0 && $diff > 0; $i--) { $reduce = min($diff, $step); $parts[$i] -= $reduce; $diff -= $reduce; }
        return $parts;
    }

    /**
     * Capture pleine page (PNG) de la blade print rendue multi‑pages.
     */
    public function screenshotForTraite(Traite $traite): Response
    {
        $nodeBinary = env('NODE_BINARY', 'C:\\Program Files\\nodejs\\node.exe');
        $npmBinary = env('NPM_BINARY', 'C:\\Program Files\\nodejs\\npm.cmd');
        $chromiumPath = env('CHROMIUM_PATH');

        try {
            // HTML imprimable (une longue page avec sauts)
            $totalTranches = max(1, (int) ($traite->nombre_traites ?? 1));
            $emission = $traite->date_emission ? Carbon::parse($traite->date_emission) : null;
            $firstDue = $traite->echeance ? Carbon::parse($traite->echeance) : null;
            $total = (int) round($traite->montant ?? 0);
            $tranches = $this->splitAmountIntoTranches($total, $totalTranches);

            $htmlParts = [];
            for ($i = 1; $i <= $totalTranches; $i++) {
                $dueDate = $firstDue ? $firstDue->copy()->addMonthsNoOverflow($i - 1) : null;
                $amountForThisTranche = $tranches[$i - 1] ?? 0;
                $data = [
                    'rangeText' => $i . ' | ' . $totalTranches,
                    'ville' => 'Douala',
                    'date_emission' => $emission ? $emission->format('d/m/Y') : '',
                    'echeance' => $dueDate ? $dueDate->format('d/m/Y') : '',
                    'montant_tranche' => number_format($amountForThisTranche, 0, ',', ' '),
                    'montant_tranche_words' => strtoupper($this->numberToFrenchWords($amountForThisTranche)),
                    'nom_raison_sociale' => $traite->nom_raison_sociale ?? '',
                    'domiciliation' => $traite->domiciliation_bancaire ?? '',
                    'rib' => $traite->rib ?? '',
                    'numero' => $traite->numero ?? '',
                    'date_emission_text_long' => $emission ? $emission->locale('fr')->translatedFormat('d F Y') : '',
                ];
                $htmlParts[] = view('traites.print', $data)->render();
                if ($i < $totalTranches) { $htmlParts[] = '<div style="page-break-after: always;"></div>'; }
            }
            $html = implode("\n", $htmlParts);

            $shot = Browsershot::html($html)
                ->emulateMedia('screen')
                ->showBackground()
                ->windowSize(1920, 3000) // Taille plus grande pour une meilleure qualité
                ->deviceScaleFactor(3) // Qualité plus élevée
                ->timeout(180)
                ->setDelay(500)
                ->setOption('waitUntil', 'networkidle0')
                ->setNodeBinary($nodeBinary)
                ->setNpmBinary($npmBinary)
                ->setOption('args', ['--no-sandbox', '--disable-setuid-sandbox', '--disable-web-security'])
                ->userAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36')
                ->fullPage();
            if (! empty($chromiumPath)) { $shot->setChromiumPath($chromiumPath); }
            $base64 = $shot->base64Screenshot();
            $png = base64_decode($base64);
            return new Response($png, 200, [
                'Content-Type' => 'image/png',
                'Content-Disposition' => 'attachment; filename="traites_'.$traite->id.'.png"',
            ]);
        } catch (\Throwable $e) {
            return new Response(json_encode([
                'status' => 'error',
                'message' => 'Echec capture PNG via Browsershot',
                'error' => $e->getMessage(),
            ], JSON_PRETTY_PRINT), 500, ['Content-Type' => 'application/json; charset=utf-8']);
        }
    }

    /**
     * Capture la blade en PNG puis l'intègre dans un PDF (une page par pleine image).
     */
    public function screenshotPdfForTraite(Traite $traite): Response
    {
        // Vérification de la disponibilité de Browsershot
        if (!class_exists(\Spatie\Browsershot\Browsershot::class)) {
            return new Response(json_encode([
                'status' => 'error',
                'message' => 'Browsershot non installé. Installez spatie/browsershot.',
            ], JSON_PRETTY_PRINT), 500, ['Content-Type' => 'application/json; charset=utf-8']);
        }

        $nodeBinary = env('NODE_BINARY', 'C:\\Program Files\\nodejs\\node.exe');
        $npmBinary = env('NPM_BINARY', 'C:\\Program Files\\nodejs\\npm.cmd');
        $chromiumPath = env('CHROMIUM_PATH');

        // Vérification des binaires
        if (!file_exists($nodeBinary)) {
            return new Response(json_encode([
                'status' => 'error',
                'message' => 'Node.js non trouvé à: ' . $nodeBinary,
                'suggestion' => 'Installez Node.js ou configurez NODE_BINARY dans .env'
            ], JSON_PRETTY_PRINT), 500, ['Content-Type' => 'application/json; charset=utf-8']);
        }

        try {
            // Préparer les pages (une par tranche) et capturer chaque page séparément
            $totalTranches = max(1, (int) ($traite->nombre_traites ?? 1));
            $emission = $traite->date_emission ? \Illuminate\Support\Carbon::parse($traite->date_emission) : null;
            $firstDue = $traite->echeance ? \Illuminate\Support\Carbon::parse($traite->echeance) : null;
            $total = (int) round($traite->montant ?? 0);
            $tranches = $this->splitAmountIntoTranches($total, $totalTranches);

            $imageBlocks = [];
            for ($i = 1; $i <= $totalTranches; $i++) {
                $dueDate = $firstDue ? $firstDue->copy()->addMonthsNoOverflow($i - 1) : null;
                $amountForThisTranche = $tranches[$i - 1] ?? 0;
                $data = [
                    'rangeText' => $i . ' | ' . $totalTranches,
                    'ville' => 'Douala',
                    'date_emission' => $emission ? $emission->format('d/m/Y') : '',
                    'echeance' => $dueDate ? $dueDate->format('d/m/Y') : '',
                    'montant_tranche' => number_format($amountForThisTranche, 0, ',', ' '),
                    'montant_tranche_words' => strtoupper($this->numberToFrenchWords($amountForThisTranche)),
                    'nom_raison_sociale' => $traite->nom_raison_sociale ?? '',
                    'domiciliation' => $traite->domiciliation_bancaire ?? '',
                    'rib' => $traite->rib ?? '',
                    'numero' => $traite->numero ?? '',
                    'date_emission_text_long' => $emission ? $emission->locale('fr')->translatedFormat('d F Y') : '',
                ];
                $pageHtml = view('traites.print', $data)->render();

                $shot = Browsershot::html($pageHtml)
                    ->emulateMedia('screen')
                    ->showBackground()
                    ->windowSize(1400, 1980) // Taille légèrement augmentée pour une meilleure qualité
                    ->deviceScaleFactor(1.5) // Qualité légèrement augmentée
                    ->timeout(90) // Timeout légèrement augmenté
                    ->setDelay(300) // Délai légèrement augmenté
                    ->setOption('waitUntil', 'domcontentloaded')
                    ->setNodeBinary($nodeBinary)
                    ->setNpmBinary($npmBinary)
                    ->setOption('args', [
                        '--no-sandbox', 
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--no-first-run',
                        '--disable-default-apps'
                    ])
                    ->userAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
                if (! empty($chromiumPath)) { $shot->setChromiumPath($chromiumPath); }

                $b64 = $shot->base64Screenshot();
                $imageBlocks[] = '<img src="data:image/png;base64,'.$b64.'" />';
            }

            // Compose un PDF multi-pages (une image par page), rempli en plein A4
            $pagesHtml = [];
            foreach ($imageBlocks as $imgTag) {
                $pagesHtml[] = '<div class="page"><div class="page-inner">'.$imgTag.'</div></div>';
            }
            $html = '<!DOCTYPE html><html><head><meta charset="utf-8">'
                  . '<style>'
                  . '@page{size:A4;margin:0}'
                  . 'html,body{margin:0;padding:0;background:#fff}'
                  . '.page{width:210mm;height:297mm;overflow:hidden;page-break-after:always;background:#fff;}'
                  . '.page-inner{width:210mm;height:297mm;overflow:hidden;position:relative;background:#fff;}'
                  . '.page-inner img{position:absolute;top:0;right:2px;width:1550px;height:2300px;display:block;object-fit:cover;object-position:center;transform:scale(1.15);transform-origin:top left;}'
                  . '</style>'
                  . '</head><body>'.implode('', $pagesHtml).'</body></html>';

            $pdf = Pdf::loadHTML($html)->setPaper('a4')->setOptions(['dpi' => 150, 'isRemoteEnabled' => true]);
            return new Response($pdf->output(), 200, [
                'Content-Type' => 'application/pdf',
                'Content-Disposition' => 'attachment; filename="traites_'.$traite->id.'.pdf"',
            ]);
        } catch (\Throwable $e) {
            \Log::error('Erreur génération PDF screenshot: ' . $e->getMessage(), [
                'traite_id' => $traite->id,
                'trace' => $e->getTraceAsString()
            ]);
            
            // Fallback: utiliser DomPDF directement
            try {
                return $this->fallbackPdfGeneration($traite);
            } catch (\Throwable $fallbackError) {
                \Log::error('Erreur fallback PDF: ' . $fallbackError->getMessage());
                
                return new Response(json_encode([
                    'status' => 'error',
                    'message' => 'Echec génération PDF. Browsershot et DomPDF ont échoué.',
                    'error' => $e->getMessage(),
                    'fallback_error' => $fallbackError->getMessage(),
                    'suggestion' => 'Vérifiez que Node.js et Chrome/Chromium sont installés et accessibles.'
                ], JSON_PRETTY_PRINT), 500, ['Content-Type' => 'application/json; charset=utf-8']);
            }
        }
    }

    /**
     * Méthode de fallback utilisant DomPDF directement
     */
    private function fallbackPdfGeneration(Traite $traite): Response
    {
        $totalTranches = max(1, (int) ($traite->nombre_traites ?? 1));
        $emission = $traite->date_emission ? \Illuminate\Support\Carbon::parse($traite->date_emission) : null;
        $firstDue = $traite->echeance ? \Illuminate\Support\Carbon::parse($traite->echeance) : null;
        $total = (int) round($traite->montant ?? 0);
        $tranches = $this->splitAmountIntoTranches($total, $totalTranches);

        $htmlParts = [];
        for ($i = 1; $i <= $totalTranches; $i++) {
            $dueDate = $firstDue ? $firstDue->copy()->addMonthsNoOverflow($i - 1) : null;
            $amountForThisTranche = $tranches[$i - 1] ?? 0;
            $data = [
                'rangeText' => $i . ' | ' . $totalTranches,
                'ville' => 'Douala',
                'date_emission' => $emission ? $emission->format('d/m/Y') : '',
                'echeance' => $dueDate ? $dueDate->format('d/m/Y') : '',
                'montant_tranche' => number_format($amountForThisTranche, 0, ',', ' '),
                'montant_tranche_words' => strtoupper($this->numberToFrenchWords($amountForThisTranche)),
                'nom_raison_sociale' => $traite->nom_raison_sociale ?? '',
                'domiciliation' => $traite->domiciliation_bancaire ?? '',
                'rib' => $traite->rib ?? '',
                'numero' => $traite->numero ?? '',
                'date_emission_text_long' => $emission ? $emission->locale('fr')->translatedFormat('d F Y') : '',
            ];
            $htmlParts[] = view('traites.print', $data)->render();
            if ($i < $totalTranches) {
                $htmlParts[] = '<div style="page-break-after: always;"></div>';
            }
        }
        $html = implode("\n", $htmlParts);

        $pdf = Pdf::loadHTML($html)->setPaper('a4')->setOptions(['dpi' => 150]);
        return new Response($pdf->output(), 200, [
            'Content-Type' => 'application/pdf',
            'Content-Disposition' => 'attachment; filename="traites_'.$traite->id.'.pdf"',
        ]);
    }
}


